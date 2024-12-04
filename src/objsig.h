#include <gelf.h>
#include <libelf.h>
#include <string.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "signature.h"

auto ProcessLibrary(const char *path) -> std::vector<sig_object>;

auto ObjSigAnalyze(const char *path) -> bool;
