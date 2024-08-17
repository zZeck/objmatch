Find sections from libraries within a binary, and output the information in Splat's yaml format.

Feedback, bug reports, and suggestions welcomed.

Build with CMake.
Requires C++20.

Dependencies:
boost/crc.hpp (to be replaced with FLIRT system from Rizin)
yaml-cpp/yaml.h
libelf

Create object signature file using objsig with a library archive.
out/build/Clang\ 17.0.6\ x86_64-pc-linux-gnu/objsig -l libultra_rom.a > 2.0I_libultra_rom.sig

Search a rom for the object file sections from the library, using the signatures.
out/build/Clang\ 17.0.6\ x86_64-pc-linux-gnu/objmatch ../baserom.z64 -l 2.0I_libultra_rom.sig > splat.yaml

Output example:

- {start: 0x249d4, vram: 0x8005e754, type: .text, name: sched.o}
- {start: 0x25314, vram: 0x8005f094, type: bin, name: 0x25314}
- {start: 0x52cf4, vram: 0x8008ca74, type: .text, name: env.o}
- {start: 0x53954, vram: 0x8008d6d4, type: bin, name: 0x53954}
- {start: 0x5509c, vram: 0x8008ee1c, type: .text, name: synthesizer.o}
- {start: 0x5577c, vram: 0x8008f4fc, type: bin, name: 0x5577c}
- {start: 0x79300, vram: 0x800b3080, type: .text, name: createmesgqueue.o}
- {start: 0x79330, vram: 0x800b30b0, type: .text, name: seteventmesg.o}
- {start: 0x793a0, vram: 0x800b3120, type: .text, name: controller.o}
- {start: 0x796e0, vram: 0x800b3460, type: bin, name: 0x796e0}
