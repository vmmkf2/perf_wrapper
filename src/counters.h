#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct CounterConfig {
  std::string name;
  uint32_t type;
  uint64_t config;
};

bool add_counter_by_name(const std::string &name, std::vector<CounterConfig> &options);
std::string build_counter_help_footer();
