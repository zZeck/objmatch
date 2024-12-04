#include <cstring>

#include <cstdio>
#include <cstdlib>

#include "objmatch.h"

auto main(int argc, const char* argv[]) -> int {
  const std::span<const char *> args = {argv, 3};
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

  binPath = args[1];

  const char * libPath = "";
  for (int argi = 2; argi < argc; argi++) {
    if (args[argi][0] != '-') {
      printf("Error: Unexpected '%s' in command line\n", args[argi]);
      return EXIT_FAILURE;
    }

    if (strlen(&args[argi][1]) != 1) {
      printf("Error: Invalid switch '%s'\n", args[argi]);
      return EXIT_FAILURE;
    }

    switch (args[argi][1]) {
      case 'l':
        if (argi + 1 >= argc) {
          printf("Error: No path specified for '-l'\n");
        }
        libPath = args[argi + 1];
        argi++;
        break;
      case 'h':
        if (argi + 1 >= argc) {
          printf("Error: No header size specified for '-h'\n");
          return EXIT_FAILURE;
        }
        argi++;
        break;
      default:
        printf("Error: Invalid switch '%s'\n", args[argi]);
        return EXIT_FAILURE;
    }
  }

  if (!ObjMatchBloop(binPath, libPath)) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
