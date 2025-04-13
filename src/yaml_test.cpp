#include <catch2/catch_test_macros.hpp>
#include <print>
#include <vector>
#include <string_view>
#include "signature.h"
#include "section_pattern.h"

TEST_CASE("Deserialize yaml", "[yaml]") {
  std::string yaml{
      "- file: blah.o\n"
      "  sections:\n"
      "    - size: 128\n"
      "      name: .text\n"
      "      symbols:\n"
      "        - offset: 0\n"
      "          size: 64\n"
      "          crc_8: 32\n"
      "          crc_all: 16\n"
      "          duplicate_crc: false\n"
      "          symbol: somefunction\n"
      "          relocations:\n"
      "            - type: 5\n"
      "              offset: 2\n"
      "              addend: 0\n"
      "              local: true\n"
      "              name: .rodata\n"};
  std::vector<char> yaml_bytes{yaml.begin(), yaml.end()};

  auto result = sig_yaml::deserialize(yaml_bytes);

  std::vector<sig_object> expect{sig_object{
      .file{"blah.o"},
      .sections{sig_section{.size = 128,
                            .name{".text"},
                            .symbols{sig_symbol{.offset = 0,
                                                .size = 64,
                                                .crc_8 = 32,
                                                .crc_all = 16,
                                                .duplicate_crc = false,
                                                .symbol{"somefunction"},
                                                .relocations{sig_relocation{.type = 5, .offset = 2, .addend = 0, .local = true, .name{".rodata"}}}}}}}}};

  REQUIRE(result == expect);
}

TEST_CASE("Serialize yaml", "[yaml]") {
  std::vector<sig_object> sig_objs{sig_object{
      .file{"blah.o"},
      .sections{sig_section{.size = 128,
                            .name{".text"},
                            .symbols{sig_symbol{.offset = 0,
                                                .size = 64,
                                                .crc_8 = 32,
                                                .crc_all = 16,
                                                .duplicate_crc = false,
                                                .symbol{"somefunction"},
                                                .relocations{sig_relocation{.type = 5, .offset = 2, .addend = 0, .local = true, .name{".rodata"}}}}}}}}};

  auto result = sig_yaml::serialize(sig_objs);

  std::string yaml{
      "- file: blah.o\n"
      "  sections:\n"
      "    - size: 128\n"
      "      name: .text\n"
      "      symbols:\n"
      "        - offset: 0\n"
      "          size: 64\n"
      "          crc_8: 32\n"
      "          crc_all: 16\n"
      "          duplicate_crc: false\n"
      "          symbol: somefunction\n"
      "          relocations:\n"
      "            - type: 5\n"
      "              offset: 2\n"
      "              addend: 0\n"
      "              local: true\n"
      "              name: .rodata\n"};
  std::vector<char> yaml_bytes{yaml.begin(), yaml.end()};

  REQUIRE(result == yaml_bytes);
}

TEST_CASE("Serialize section_pattern yaml", "[yaml]") {
  std::vector<section_pattern> section_patterns{section_pattern{
    .object{"someobj"},
    .section{"section"},
    .size{0xFF},
    .crc_8{0x1},
    .crc_all{0x2},
    .relocations{{
      sec_relocation{
        .type{},
        .offset{},
        .addend{},
      }
    }}
  }};

  auto result = pattern_yaml::serialize(section_patterns);

  std::string yaml{
      "- object: someobj\n"
      "  section: section\n"
      "  size: 0xff\n"
      "  crc_8: 0x1\n"
      "  crc_all: 0x2\n"
  };
  std::vector<char> yaml_bytes{yaml.begin(), yaml.end()};

  REQUIRE(result == yaml_bytes);
}


