#include <gelf.h>
#include <libelf.h>
#include <string.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "signature.h"

std::vector<sig_object> ProcessLibrary(const char *path);

auto ObjSigAnalyze(const char *path) -> bool;
