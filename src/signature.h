#include <cstdint>
#include <string>
#include <vector>

using sig_relocation = struct sig_relocation {
  uint64_t type{};
  uint64_t offset{};
  uint32_t addend{};
  bool local{};
  std::string name;

  auto operator==(const sig_relocation &x) const -> bool  = default;
};

using sig_symbol = struct sig_symbol {
  uint64_t offset{};
  uint64_t size{};
  uint32_t crc_8{};
  uint32_t crc_all{};
  bool duplicate_crc{};
  std::string symbol;
  std::vector<sig_relocation> relocations;

  auto operator==(const sig_symbol &x) const -> bool  = default;
};

using sig_section = struct sig_section {
  uint64_t size{};
  std::string name;
  std::vector<sig_symbol> symbols;

  auto operator==(const sig_section &x) const -> bool  = default;
};

using sig_object = struct sig_object {
  std::string file;
  std::vector<sig_section> sections;

  auto operator==(const sig_object &x) const -> bool  = default;
};

namespace sig_yaml {
    auto deserialize(std::vector<char> &bytes) -> std::vector<sig_object>;
    auto serialize(const std::vector<sig_object> &sig_obj) -> std::vector<char>;
}