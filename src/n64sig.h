#include <gelf.h>
#include <libelf.h>
#include <string.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "signature.h"

using n64sig_output_fmt_t = enum { N64SIG_FMT_DEFAULT, N64SIG_FMT_JSON };

class CN64Sig {
  std::vector<const char *> m_LibPaths;

  n64sig_output_fmt_t m_OutputFormat{N64SIG_FMT_DEFAULT};

  std::vector<sig_object> ProcessLibrary(const char *path);

 public:
  void AddLibPath(const char *path);
  auto SetOutputFormat(const char *format) -> bool;
  auto Run() -> bool;
};
