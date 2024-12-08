#include <cstring>

#include <cstdio>
#include <cstdlib>
#include <print>

#include "objmatch.h"

auto main(int argc, const char* argv[]) -> int {
  const std::span<const char *> args = {argv, 3};
  const char* binPath = nullptr;

  if (argc < 2) {
    std::print(
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
      std::println("Error: Unexpected '{}' in command line", args[argi]);
      return EXIT_FAILURE;
    }

    if (strlen(&args[argi][1]) != 1) {
      std::println("Error: Invalid switch '{}'", args[argi]);
      return EXIT_FAILURE;
    }

    switch (args[argi][1]) {
      case 'l':
        if (argi + 1 >= argc) {
          std::println("Error: No path specified for '-l'");
        }
        libPath = args[argi + 1];
        argi++;
        break;
      case 'h':
        if (argi + 1 >= argc) {
          std::println("Error: No header size specified for '-h'");
          return EXIT_FAILURE;
        }
        argi++;
        break;
      default:
        std::println("Error: Invalid switch '{}'", args[argi]);
        return EXIT_FAILURE;
    }
  }

  if (!ObjMatchBloop(binPath, libPath)) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
