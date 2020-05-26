# Fingerprint

![build status](https://github.com/andrewstucki/fingerprint/workflows/Test/badge.svg)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fandrewstucki%2Ffingerprint.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fandrewstucki%2Ffingerprint?ref=badge_shield)

This repo serves as an experimental library for fingerprinting various
files similar to how VirusTotal does.

Besides some general file hashes and file type analysis, it contains
some additional parsing modules for Elf, PE, and Mach-o binaries. Included
in these are section entropy calculations and imported/exported symbols.
Additionally it has implementations of telfhash (Elf), imphash (PE), and
symhash (Mach-o) fuzzy symbol hashing algorithms that are fairly useful
in malware analysis.

The only dependency required is the [capstone library](https://github.com/aquynh/capstone) (used for enumerating
call sites through disassembling stripped elf binaries for telfhash calculations).


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fandrewstucki%2Ffingerprint.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fandrewstucki%2Ffingerprint?ref=badge_large)