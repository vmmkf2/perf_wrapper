#include "counters.h"

#include <linux/perf_event.h>

#include <algorithm>
#include <cctype>
#include <sstream>

namespace {
struct CounterNameEntry {
  const char *name;
  uint32_t type;
  uint64_t config;
};

constexpr CounterNameEntry kSupportedCounters[] = {
    {"sw-cpu-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK},
    {"sw-task-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK},
    {"sw-page-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS},
    {"sw-page-faults-min", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN},
    {"sw-page-faults-maj", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ},
    {"sw-context-switches", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES},
    {"sw-cpu-migrations", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS},
    {"sw-alignment-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_ALIGNMENT_FAULTS},
    {"sw-emulation-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_EMULATION_FAULTS},
    {"sw-dummy", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_DUMMY},
    {"sw-bpf-output", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_BPF_OUTPUT},
    {"hw-cpu-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"hw-instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"hw-cache-references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES},
    {"hw-cache-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES},
    {"hw-branch-instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"hw-branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"hw-bus-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BUS_CYCLES},
    {"hw-stalled-cycles-frontend", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND},
    {"hw-stalled-cycles-backend", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND},
    {"hw-ref-cpu-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_REF_CPU_CYCLES},
};

std::string trim_copy(const std::string &value) {
  const auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch); });
  const auto end =
      std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) { return std::isspace(ch); }).base();
  if (begin >= end) {
    return "";
  }
  return std::string(begin, end);
}

std::string to_lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return value;
}

std::string list_counters_by_type(uint32_t type) {
  std::ostringstream oss;
  bool first = true;
  for (const auto &entry : kSupportedCounters) {
    if (entry.type != type) {
      continue;
    }
    if (!first) {
      oss << ", ";
    }
    oss << entry.name;
    first = false;
  }
  if (first) {
    oss << "(none)";
  }
  return oss.str();
}
} // namespace

bool add_counter_by_name(const std::string &name, std::vector<CounterConfig> &counters) {
  const std::string normalized = to_lower_copy(trim_copy(name));
  if (normalized.empty()) {
    return false;
  }

  for (const auto &entry : kSupportedCounters) {
    if (normalized == entry.name) {
      counters.push_back({entry.name, entry.type, entry.config});
      return true;
    }
  }
  return false;
}

std::string build_counter_help_footer() {
  std::ostringstream oss;
  oss << "\nSoftware counters: " << list_counters_by_type(PERF_TYPE_SOFTWARE)
      << "\nHardware counters: " << list_counters_by_type(PERF_TYPE_HARDWARE);
  return oss.str();
}
