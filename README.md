# RDPWrapOffsetFinder

Automatically find offsets needed by RDPWrap and generate rdpwrap.ini

## Usage

Pass the path of termsrv.dll as command line argument. If not provided, default to current system's termsrv.dll in System32 directory.

## Compile

This project depends on [zydis](https://github.com/zyantific/zydis), you needed to build zydis first.

1. Use `git submodule update --init --recursive` to initialize the submodule

2. Open `zydis\msvc\Zydis.sln` and build DLL version of zydis

3. Open `RDPWrapOffsetFinder.sln` and start build

4. After build, copy `dbghelp.dll` `symsrv.dll` `symsrv.yes` (you can find them in Windows SDK) and `Zydis.dll` (also `Zydis.pdb` if you want to debug) to the same directory of the EXE file

## Notes

- PDB symbol of `termsrv.dll` is needed. If the program outputs "Symbol not found", check your Internet connection to Microsoft symbol server. You can manually set environment variable `_NT_SYMBOL_PATH` to use a symbol proxy

- If the required symbol is not available, you can try the `_nosymbol` version which manually search pattens. Using the `_nosymbol` version with 32bit binaries is not widely tested and may return wrong results
