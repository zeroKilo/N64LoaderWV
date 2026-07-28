# N64 ROM Loader for Ghidra by Warranty Voider

this is a loader module for ghidra for N64 roms (.z64, .n64, .v64)
- fixes endianess (little, big, mixed) at loading
- loads ram, rom and boot section into ghidra
- it can use a signature/pattern file to scan for symbol hints for ghidra

this allows a rom to be labeled, disassembled and decompiled

## Function discovery and runtime-loaded code

The loader creates the N64 memory map and marks the ROM entry point. Ghidra
then discovers functions reachable through direct references; importing a ROM
does not prove every function boundary. Code that the game decompresses,
relocates, or loads as an overlay is not present at its runtime address in the
initial ROM-to-RAM image.

For those games, capture an RDRAM dump after the code of interest has been
loaded and select it with the `RDRAM dump file` loader option. Dumps must be
exactly 4 MiB (base memory) or 8 MiB (Expansion Pak). The loader maps the
interrupt vectors at `0x80000000` and the remaining bytes at `0x80000400`
without padding the dump. A dump represents one runtime moment, so overlays
that reuse an address may require separate projects or snapshots.

The `Signature file` option can also consume an N64sym address/name file or a
byte-pattern file to seed known functions. These inputs are hints for Ghidra;
they do not establish that every possible function has been found.

Headless imports can pass the same inputs as `-loader-rdram <path>`,
`-loader-signature <path>`, `-loader-pif <path>`, and
`-loader-modem <path>` after selecting `-loader N64LoaderWVLoader`.

credits:
- [blackgamma7](https://github.com/blackgamma7) for fixing memory layout stuff, adding register symbols and various small changes [see merge commit](https://github.com/zeroKilo/N64LoaderWV/commit/46137048775a41f4b54c08cf3c3fab1bcb962219)
- [dmattia](https://github.com/dmattia) for adding build instructions for mac

Ghidra 12.1 requires JDK 21. Use the JDK version required by your Ghidra release.

[![Alt text](https://img.youtube.com/vi/3d3a39LuCwc/0.jpg)](https://www.youtube.com/watch?v=3d3a39LuCwc)

[![Alt text](https://img.youtube.com/vi/fhI3Vpw7FVk/0.jpg)](https://www.youtube.com/watch?v=fhI3Vpw7FVk)

## Build from Source (Mac)

```bash
brew install java
brew install gradle
brew cask install ghidra

export GHIDRA_INSTALL_DIR=`brew cask ls ghidra | grep ghidra | sed 's/^.*-> \(.*\)ghidraRun.*/\1/'`
```

Then whenever you're ready to build, run

```bash
gradle
```

and it will create a zip file in `/dist` that you can use that file as the extension in Ghidra
