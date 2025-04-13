#include <vector>
#include <cstdint>
#include <string>

using sec_relocation = struct sec_relocation {
  uint64_t type{};
  uint64_t offset{};
  uint32_t addend{};

  auto operator==(const sec_relocation &x) const -> bool  = default;
};


using section_pattern = struct section_pattern {
  std::string object;
  std::string section;
  uint64_t size{};
  uint32_t crc_8{};
  uint32_t crc_all{};
  std::vector<sec_relocation> relocations;

  auto operator==(const section_pattern &x) const -> bool  = default;
};

namespace pattern_yaml {
  auto serialize(const std::vector<section_pattern> &patterns) -> std::vector<char>;
}
