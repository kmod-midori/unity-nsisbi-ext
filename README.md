# `nsisbi-ext`
Extract files from Unity NSIS installer created with the NSISBI format (i.e. can not be extracted with 7zip).

```
Usage: nsisbi-ext [OPTIONS] <FILE> <OUT_DIR>

Arguments:
  <FILE>     Unity NSIS installer file
  <OUT_DIR>  Output directory

Options:
  -r, --regex <REGEX>  Regex to filter files
  -h, --help           Print help
  -V, --version        Print version
```