# NigelCrypt SDK

This SDK bundle includes headers, tools, and examples. It does **not** include prebuilt `.lib`/`.dll` because this environment cannot build Windows binaries.

## Contents
- `include/nigelcrypt/nigelcrypt.hpp`
- `examples/example.cpp`
- `tools/nigelcrypt_pack.cpp`
- `tools/pack_sample.ps1`
- `lib/` (empty placeholder for your built libs)

## Build (Windows)
Use the repo root CMake to build static/shared libs and tools:

```
cmake -S .. -B build -DNIGELCRYPT_BUILD_SHARED=ON -DNIGELCRYPT_BUILD_STATIC=ON -DNIGELCRYPT_BUILD_TOOLS=ON -DNIGELCRYPT_BUILD_EXAMPLES=ON
cmake --build build --config Release
```

Then copy build outputs into `sdk/lib` as needed.

## Example Usage
See `examples/example.cpp` for full usage across:
- Build-time packed blobs
- AAD
- Policy enforcement
- Region policy (best-effort)
- Runtime binding
- Memory-hardened buffers
- Rekey

## Notes
- Build-time packing keeps plaintext out of the binary.
- Region policy is application-defined and best-effort.

## C API
See include/nigelcrypt/nigelcrypt_c.h and examples/example_c.c
