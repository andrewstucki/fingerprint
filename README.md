# Fingerprint

This repo serves as an experimental library for fingerprinting various
files similar to how VirusTotal does.

Besides some general file hashes and file type analysis, it contains
some additional parsing modules for Elf, PE, and Mach-o binaries. Included
in these are section entropy calculations and imported/exported symbols.
Additionally it has implementations of telfhash (Elf), imphash (PE), and
symhash (Mach-o) fuzzy symbol hashing algorithms that are fairly useful
in malware analysis.

The only dependency required is the capstone library (used for enumerating
call sites through disassembling stripped elf binaries for telfhash calculations).
