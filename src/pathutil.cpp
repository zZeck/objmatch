#include "pathutil.h"

#include <cstring>

// returns true if 'str' ends with 'suffix'
static auto EndsWith(const char *str, const char *suffix) -> bool {
  if ((str == nullptr) || (suffix == nullptr)) {
    return false;
  }
  size_t const len_str = strlen(str);
  size_t const len_suffix = strlen(suffix);
  if (len_suffix > len_str) {
    return false;
  }
  return (0 == strncmp(str + len_str - len_suffix, suffix, len_suffix));
}

// extracts file name without extension
auto PathGetFileName(const char *path, char *dstName, size_t maxLength) -> size_t {
  if (path == nullptr) {
    return 0;
  }

  size_t i = strlen(path);

  if (i == 0) {
    return 0;
  }

  const char *start = path;

  while ((i--) != 0u) {
    if (path[i] == '/' || path[i] == '\\') {
      start = &path[i + 1];
      break;
    }
  }

  const char *end = strchr(&path[i + 1], '.');

  if ((end == nullptr) || static_cast<size_t>((end - start) + 1) >= maxLength) {
    strncpy(dstName, start, maxLength);
    return maxLength;
  }

  strncpy(dstName, start, end - start);
  dstName[end - start] = '\0';
  return end - start;
}

auto PathIsStaticLibrary(const char *path) -> bool {
  if (strlen(path) < 3) {
    return false;
  }
  return EndsWith(path, ".a") || EndsWith(path, ".A");
}

auto PathIsObjectFile(const char *path) -> bool {
  if (strlen(path) < 3) {
    return false;
  }
  return EndsWith(path, ".o") || EndsWith(path, ".O");
}

auto PathIsSignatureFile(const char *path) -> bool {
  if (strlen(path) < 5) {
    return false;
  }
  return EndsWith(path, ".sig") || EndsWith(path, ".SIG");
}

auto PathIsN64Rom(const char *path) -> bool {
  if (strlen(path) < 5) {
    return false;
  }

  return (EndsWith(path, ".z64") || EndsWith(path, ".n64") || EndsWith(path, ".v64") || EndsWith(path, ".Z64") || EndsWith(path, ".N64") ||
          EndsWith(path, ".V64"));
}

auto IsFileWithSymbols(const char *path) -> bool { return PathIsStaticLibrary(path) || PathIsObjectFile(path) || PathIsSignatureFile(path); }
