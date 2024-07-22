#ifndef PATHUTIL_H
#define PATHUTIL_H

#include <cstddef>

auto PathIsStaticLibrary(const char *path) -> bool;
auto PathIsObjectFile(const char *path) -> bool;
auto PathIsSignatureFile(const char *path) -> bool;
auto PathIsN64Rom(const char *path) -> bool;
auto PathGetFileName(const char *path, char *dstName, size_t maxLength) -> size_t;
auto IsFileWithSymbols(const char *path) -> bool;

#endif  // PATHUTIL_H
