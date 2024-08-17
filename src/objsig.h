#include <gelf.h>
#include <libelf.h>
#include <string.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "signature.h"

class ObjSig {
  std::vector<const char *> m_LibPaths;

  std::vector<sig_object> ProcessLibrary(const char *path);

 public:
  void AddLibPath(const char *path);
  auto Run() -> bool;
};
