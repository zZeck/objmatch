#include <string.h>

#include <cstdio>
#include <cstdlib>

#include "objsig.h"

auto main(int argc, const char *argv[]) -> int {
  if (argc < 2) {
    printf(
        "objsig - signature file generator for objsym ()\n\n"
        "  Usage: objsig [options]\n\n"
        "  Options:\n"
        "    -l <lib path>     add a library path\n");

    return EXIT_FAILURE;
  }

  ObjSig objsig;

  for (int argi = 1; argi < argc; argi++) {
    // printf("[%s]\n", argv[argi]);

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
        objsig.AddLibPath(argv[argi + 1]);
        argi++;
        break;
    }
  }

  objsig.Run();

  return EXIT_SUCCESS;
}
