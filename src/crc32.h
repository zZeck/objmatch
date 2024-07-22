#ifndef CRC32_H
#define CRC32_H

#include <cstddef>
#include <cstdint>

auto crc32(const uint8_t *bytes, size_t length) -> uint32_t;
auto crc32_begin() -> uint32_t;
void crc32_read(const uint8_t *bytes, size_t length, uint32_t *result);
void crc32_end(uint32_t *result);

#endif  // CRC32_H
