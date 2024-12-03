#include <string.h>

#include <cstdio>
#include <cstdlib>

#include "objmatch.h"

auto main(int argc, const char* argv[]) -> int {
  const char* binPath = nullptr;

  if (argc < 2) {
    printf(
        "objmatch - Library object file section finder ()\n\n"
        "  Usage: objmatch <binary path> [options]\n\n"
        "  Options:\n"
        "    -l <sig path>      scan for symbols from signature file(s)\n"
        "    -h <headersize>            set the headersize (default: 0x80000000)\n");

    return EXIT_FAILURE;
  }

  binPath = argv[1];

  //if (!objmatch.LoadBinary(binPath)) {
  //  printf("Error: Failed to load '%s'\n", binPath);
  //  return EXIT_FAILURE;
  //}

  const char * libPath = "";
  const char * headerSize = "0";
  for (int argi = 2; argi < argc; argi++) {
    if (argv[argi][0] != '-') {
      printf("Error: Unexpected '%s' in command line\n", argv[argi]);
      return EXIT_FAILURE;
    }

    if (strlen(&argv[argi][1]) != 1) {
      printf("Error: Invalid switch '%s'\n", argv[argi]);
      return EXIT_FAILURE;
    }

    switch (argv[argi][1]) {
      case 'l':
        if (argi + 1 >= argc) {
          printf("Error: No path specified for '-l'\n");
        }
        libPath = argv[argi + 1];
        //objmatch.AddLibPath(argv[argi + 1]);
        argi++;
        break;
      case 'h':
        if (argi + 1 >= argc) {
          printf("Error: No header size specified for '-h'\n");
          return EXIT_FAILURE;
        }
        //objmatch.SetHeaderSize(strtoul(argv[argi + 1], nullptr, 0));
        headerSize = argv[argi + 1];
        argi++;
        break;
      /*case 'o':
        if (argi + 1 >= argc) {
          printf("Error: No path specified for '-o'\n");
          return EXIT_FAILURE;
        }
        if (!objmatch.SetOutputPath(argv[argi + 1])) {
          printf("Error: Could not open '%s'\n", argv[argi + 1]);
          return EXIT_FAILURE;
        }
        argi++;
        break;*/
      default:
        printf("Error: Invalid switch '%s'\n", argv[argi]);
        return EXIT_FAILURE;
    }
  }

  if (!ObjMatchBloop(binPath, libPath, strtoul(headerSize, nullptr, 0))) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
