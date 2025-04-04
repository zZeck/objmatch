#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <print>
#include <span>

#include "objsig.h"

auto main(int argc, const char *argv[]) -> int {
  const std::span<const char *> args = {argv, 3};

  if (argc < 2) {
    std::print(
        "objsig - signature file generator for objsym ()\n\n"
        "  Usage: objsig [options]\n\n"
        "  Options:\n"
        "    -l <lib path>     add a library path\n");

    return EXIT_FAILURE;
  }

  for (int argi = 1; argi < argc; argi++) {
    if (args[argi][0] != '-') {
      std::println("Error: Unexpected '{}' in command line", args[argi]);
      return EXIT_FAILURE;
    }

    if (strlen(&args[argi][1]) != 1) {
      std::println("Error: Invalid switch '{}'", args[argi]);
      return EXIT_FAILURE;
    }

    if (args[argi][1] == 'l') {
      if (argi + 1 >= argc) {
        std::println("Error: No path specified for '-l'");
      }
      ObjSigAnalyze(args[argi + 1]);
      argi++;
      break;
    }
  }

  return EXIT_SUCCESS;
}
