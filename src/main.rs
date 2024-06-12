use std::{
    fs::File,
    io::{Cursor, Read, Seek},
    path::PathBuf,
};

use anyhow::Result;
use clap::Parser;
use memmap::MmapOptions;
use scroll::{IOread, Pread, SizeWith};

const NSIS_HEADER: &[u8] = b"NullsoftInst";

#[repr(C)]
#[derive(Debug, Pread, IOread, SizeWith)]
struct NsisFirstHeader {
    flags: u32,
    siginfo: u32,

    magic: [u8; 12],

    length_of_header: u32,
    length_of_all_following_data: u32,
}

#[repr(C)]
#[derive(Debug, Pread, IOread, SizeWith, Clone, Copy)]
struct NsisBlock {
    offset: u32,
    num: u32,
}

impl NsisFirstHeader {
    fn is_nsisbi(&self) -> bool {
        self.flags & 0x30 != 0
    }

    fn has_crc(&self) -> bool {
        self.flags & 0x04 != 0
    }
}

fn clear_int_flag(i: u32) -> (u32, bool) {
    let has_flag = i & 0x80000000 != 0;
    (i & !0x80000000, has_flag)
}

fn read_string(block: &[u8], is_unicode: bool, pos: u32) -> Result<String> {
    if is_unicode {
        let mut offset = pos * 2;
        let mut buf = vec![];
        for _ in 0..0xFFFF {
            let c = block.pread::<u16>(offset as usize)?;
            offset += 2;

            if c == 0x03 || c == 0x02 {
                // This is a variable
                offset += 2;
                continue;
            }

            if c == 0 {
                break;
            }
            buf.push(c);
        }
        Ok(String::from_utf16(&buf)?)
    } else {
        let mut offset = pos;
        let mut buf = vec![];
        for _ in 0..0xFFFF {
            let c = block.pread::<u8>(offset as usize)?;
            offset += 1;
            if c == 0 {
                break;
            }
            buf.push(c);
        }
        Ok(String::from_utf8(buf)?)
    }
}

fn clean_path(in_path: &str) -> String {
    in_path
        .replace('\\', "/")
        .strip_prefix('/')
        .unwrap_or(in_path)
        .to_string()
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(help = "Unity NSIS installer file")]
    file: PathBuf,

    /// Number of times to greet
    #[arg(help = "Output directory")]
    out_dir: PathBuf,

    #[arg(short, long, help = "Regex to filter files")]
    regex: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if let Some(pat) = args.regex {
        Some(regex::Regex::new(&pat)?)
    } else {
        None
    };

    // Default to INFO
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let file = File::open(args.file)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };

    let header_offset = mmap.windows(NSIS_HEADER.len()).find_map(|window| {
        if window == NSIS_HEADER {
            Some(window.as_ptr() as usize)
        } else {
            None
        }
    });

    let header_offset = if let Some(offset) = header_offset {
        offset - mmap.as_ptr() as usize - 8 // flags & siginfo
    } else {
        return Err(anyhow::anyhow!("NSIS header not found"));
    };

    let mut cursor = std::io::Cursor::new(&mmap[header_offset..]);

    log::info!("NSIS header found at offset: {:#X}", header_offset);
    let first_header = cursor.ioread::<NsisFirstHeader>()?;

    let is_nsisbi = first_header.is_nsisbi();
    log::info!("Is NSISBI: {}", is_nsisbi);
    log::info!("Has CRC: {}", first_header.has_crc());

    if is_nsisbi {
        cursor.read_exact(&mut [0; 8])?;
    }
    let (compressed_header_length, header_is_compressed) =
        clear_int_flag(cursor.ioread_with::<u32>(scroll::LE)?);
    log::info!(
        "Header is compressed: {}, size on disk: {}",
        header_is_compressed,
        compressed_header_length
    );

    let data_offset =
        header_offset + cursor.position() as usize + compressed_header_length as usize;

    let mut decompressed_header = vec![];
    lzma_rs::lzma_decompress_with_options(
        &mut Cursor::new(&mmap[header_offset + cursor.position() as usize..]),
        &mut decompressed_header,
        &lzma_rs::decompress::Options {
            unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(Some(
                first_header.length_of_header as u64,
            )),
            ..Default::default()
        },
    )?;

    let mut header_cursor = std::io::Cursor::new(&decompressed_header);
    let _header_flags = header_cursor.ioread::<u32>()?;
    let mut headers = vec![];
    for _ in 0..8 {
        headers.push(header_cursor.ioread::<NsisBlock>()?);
    }

    let entries_block = headers[2];
    let strings_block = headers[3];
    let strings_data = &decompressed_header[strings_block.offset as usize..];

    let is_unicode = decompressed_header.pread::<u16>(strings_block.offset as usize)? == 0;
    log::info!("Is Unicode: {}", is_unicode);

    let mut command_cursor = header_cursor.clone();
    command_cursor.seek(std::io::SeekFrom::Start(entries_block.offset as u64))?;

    let mut num_params = 6;
    if is_nsisbi {
        num_params += 2;
    }

    let mut current_rel_path = PathBuf::new();
    for _ in 0..entries_block.num {
        let command_id = command_cursor.ioread::<u32>()?;
        let mut params = Vec::with_capacity(num_params as usize);
        for _ in 0..num_params {
            let param = command_cursor.ioread::<u32>()?;
            params.push(param);
        }

        match command_id {
            11 => {
                // EW_CREATEDIR
                let path_str_id = params[0];
                let path_str = clean_path(&read_string(strings_data, is_unicode, path_str_id)?);
                current_rel_path = PathBuf::from(path_str);
                log::debug!("Creating directory: {:?}", current_rel_path);
            }
            20 => {
                // EW_EXTRACTFILE
                let name_str_id = params[1];
                let name_str = clean_path(&read_string(strings_data, is_unicode, name_str_id)?);

                let full_rel_path = current_rel_path.join(name_str);
                if let Some(r) = &filter {
                    if !r.is_match(&full_rel_path.to_string_lossy()) {
                        log::debug!("Skipping file: {:?}", full_rel_path);
                        continue;
                    }
                }

                let dir_abs_path = args.out_dir.join(&current_rel_path);
                std::fs::create_dir_all(&dir_abs_path)?; // Ensure directory exists

                let full_abs_path = args.out_dir.join(&full_rel_path);

                let file_size_offset = data_offset + params[2] as usize;
                let file_data_offset = file_size_offset + 4;
                let (file_size, is_compressed) =
                    clear_int_flag(mmap.pread::<u32>(file_size_offset)?);

                log::info!(
                    "Extracting file: {:?} (size: {}, compressed: {}) to {:?}",
                    full_rel_path,
                    file_size,
                    is_compressed,
                    full_abs_path
                );

                if file_size == 0 {
                    std::fs::write(full_abs_path, [])?;
                    continue;
                }

                if !is_compressed {
                    std::fs::write(
                        full_abs_path,
                        &mmap[file_data_offset..file_data_offset + file_size as usize],
                    )?;
                    continue;
                }

                let mut out_file = std::fs::File::create(&full_abs_path)?;
                lzma_rs::lzma_decompress_with_options(
                    &mut Cursor::new(
                        &mmap[file_data_offset..file_data_offset + file_size as usize],
                    ),
                    &mut out_file,
                    &lzma_rs::decompress::Options {
                        unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(None),
                        ..Default::default()
                    },
                )?;
            }
            _ => {}
        }
    }

    Ok(())
}
