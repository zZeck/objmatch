#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>

#include "objsig.h"

auto main(int argc, const char *argv[]) -> int {
  const std::span<const char *> args = {argv, 3};

  if (argc < 2) {
    printf(
        "objsig - signature file generator for objsym ()\n\n"
        "  Usage: objsig [options]\n\n"
        "  Options:\n"
        "    -l <lib path>     add a library path\n");

    return EXIT_FAILURE;
  }

  for (int argi = 1; argi < argc; argi++) {
    if (args[argi][0] != '-') {
      printf("Error: Unexpected '%s' in command line\n", args[argi]);
      return EXIT_FAILURE;
    }

    if (strlen(&args[argi][1]) != 1) {
      printf("Error: Invalid switch '%s'\n", args[argi]);
      return EXIT_FAILURE;
    }

    if (args[argi][1] == 'l') {
      if (argi + 1 >= argc) {
        printf("Error: No path specified for '-l'\n");
      }
      ObjSigAnalyze(args[argi + 1]);
      argi++;
      break;
    }
  }

  return EXIT_SUCCESS;
}
