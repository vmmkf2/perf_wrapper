#include <CLI/CLI.hpp>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <linux/perf_event.h>
#include <optional>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "counters.h"
#include "helper.h"

struct MonitorOptions {
  pid_t targetPid = 0;                 // 0 means current process
  int durationSeconds = 0;             // Optional duration for sampling existing processes
  bool hasDuration = false;            // Whether duration was explicitly provided
  std::vector<std::string> appCommand; // Command to spawn under measurement
  std::vector<CounterConfig> counters;
  std::vector<std::vector<CounterConfig>> counterGroups;
};

bool parse_counter_token(const std::string &token, std::string &name_out, bool &pinned_out) {
  std::string value = token;
  pinned_out = false;

  const auto colon_pos = value.find(':');
  if (colon_pos != std::string::npos) {
    std::string suffix = value.substr(colon_pos + 1);
    value = value.substr(0, colon_pos);

    if (suffix == "P" || suffix == "p") {
      pinned_out = true;
    } else if (!suffix.empty()) {
      std::cerr << "Error: unknown counter modifier '" << suffix << "' in token '" << token << "'" << std::endl;
      return false;
    }
  }

  name_out = value;
  return true;
}

bool build_counter_list(const std::vector<std::string> &names, std::vector<CounterConfig> &configured,
                        bool enforce_pinned_leader) {
  configured.clear();
  if (names.empty()) {
    std::cerr << "Error: no counters specified" << std::endl;
    return false;
  }

  configured.reserve(names.size());
  for (std::size_t index = 0; index < names.size(); ++index) {
    std::string parsed_name;
    bool pinned = false;
    if (!parse_counter_token(names[index], parsed_name, pinned)) {
      configured.clear();
      return false;
    }

    if (!add_counter_by_name(parsed_name, configured)) {
      std::cerr << "Error: unknown counter '" << parsed_name << "'" << std::endl;
      configured.clear();
      return false;
    }

    if (pinned) {
      if (enforce_pinned_leader && index != 0) {
        std::cerr << "Error: pinned counters must be the first entry in a group" << std::endl;
        configured.clear();
        return false;
      }
      configured.back().pinned = true;
    }
  }

  if (configured.empty()) {
    std::cerr << "Error: no counters specified" << std::endl;
    return false;
  }

  return true;
}

bool configure_counters(const std::vector<std::string> &names, MonitorOptions &options) {
  if (names.empty()) {
    return true;
  }

  std::vector<CounterConfig> configured;
  if (!build_counter_list(names, configured, false)) {
    return false;
  }

  options.counters = std::move(configured);
  return true;
}

std::vector<std::string> split_counter_spec(const std::string &spec) {
  std::vector<std::string> names;
  std::string current;
  for (char ch : spec) {
    if (ch == ',') {
      names.push_back(current);
      current.clear();
    } else {
      current.push_back(ch);
    }
  }
  names.push_back(current);

  names.erase(std::remove_if(names.begin(), names.end(), [](const std::string &value) { return value.empty(); }),
              names.end());

  return names;
}

bool configure_counter_groups(const std::vector<std::string> &group_specs, MonitorOptions &options) {
  for (const auto &spec : group_specs) {
    const auto names = split_counter_spec(spec);
    if (names.empty()) {
      std::cerr << "Error: empty counter group specified" << std::endl;
      return false;
    }

    std::vector<CounterConfig> group;
    if (!build_counter_list(names, group, true)) {
      return false;
    }
    options.counterGroups.push_back(std::move(group));
  }
  return true;
}

static long perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
  // debug print of syscall parametrs
  std::cout << "perf_event_open called with pid=" << pid << ", cpu=" << cpu << ", group_fd=" << group_fd
            << ", flags=" << flags << std::endl;
  return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

std::vector<char *> build_exec_argv(const std::vector<std::string> &command) {
  std::vector<char *> argv;
  argv.reserve(command.size() + 1);
  for (const std::string &arg : command) {
    argv.push_back(const_cast<char *>(arg.c_str()));
  }
  argv.push_back(nullptr);
  return argv;
}

bool wait_for_child_stop(pid_t child_pid) {
  int status = 0;
  if (waitpid(child_pid, &status, WUNTRACED) == -1) {
    perror("waitpid");
    return false;
  }
  if (!WIFSTOPPED(status)) {
    std::cerr << "Error: child process did not stop as expected" << std::endl;
    return false;
  }
  return true;
}

enum class ChildWaitResult { Completed, TimedOut, Error };

ChildWaitResult wait_for_child_with_timeout(pid_t child_pid, int timeoutSeconds, int &status) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSeconds);
  while (true) {
    pid_t result = waitpid(child_pid, &status, WNOHANG);
    if (result == -1) {
      perror("waitpid");
      return ChildWaitResult::Error;
    }
    if (result > 0) {
      return ChildWaitResult::Completed;
    }

    if (std::chrono::steady_clock::now() >= deadline) {
      return ChildWaitResult::TimedOut;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

void terminate_child_process(pid_t child_pid) {
  if (child_pid <= 0) {
    return;
  }

  if (kill(child_pid, SIGKILL) == -1) {
    perror("kill");
  }
}

bool launch_target_command(const MonitorOptions &options, pid_t &child_pid) {
  if (options.appCommand.empty()) {
    child_pid = -1;
    return true;
  }

  std::cout << "Running command:";
  for (const auto &arg : options.appCommand) {
    std::cout << ' ' << arg;
  }
  std::cout << std::endl;

  child_pid = fork();
  if (child_pid == -1) {
    perror("fork");
    return false;
  }

  if (child_pid == 0) {
    // Child process waits for parent to configure perf
    raise(SIGSTOP);
    std::vector<char *> exec_args = build_exec_argv(options.appCommand);
    execvp(exec_args[0], exec_args.data());
    perror("execvp");
    _exit(1);
  }

  if (!wait_for_child_stop(child_pid)) {
    kill(child_pid, SIGKILL);
    waitpid(child_pid, nullptr, 0);
    return false;
  }

  return true;
}

struct PerfHandle {
  perf_event_attr attr{};
  int fd = -1;
  std::string label;
  int groupIndex = 0;

  PerfHandle() = default;
  PerfHandle(const PerfHandle &) = delete;
  PerfHandle &operator=(const PerfHandle &) = delete;

  PerfHandle(PerfHandle &&other) noexcept
      : attr(other.attr), fd(other.fd), label(std::move(other.label)), groupIndex(other.groupIndex) {
    other.fd = -1;
    other.attr = perf_event_attr{};
    other.groupIndex = 0;
  }

  PerfHandle &operator=(PerfHandle &&other) noexcept {
    if (this != &other) {
      close_fd();
      attr = other.attr;
      fd = other.fd;
      label = std::move(other.label);
      groupIndex = other.groupIndex;
      other.fd = -1;
      other.attr = perf_event_attr{};
      other.groupIndex = 0;
    }
    return *this;
  }

  ~PerfHandle() { close_fd(); }

private:
  void close_fd() noexcept {
    if (fd >= 0) {
      close(fd);
      fd = -1;
    }
  }
};

struct CounterResult {
  std::string label;
  long long value = 0;
  uint64_t time_enabled = 0;
  uint64_t time_running = 0;
  uint64_t id = 0;
  int group_index = 0;
};

namespace {
long double nanoseconds_to_seconds(uint64_t ns) { return static_cast<long double>(ns) / 1'000'000'000.0L; }

std::string format_decimal(long double value, int precision) {
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(precision) << value;
  return oss.str();
}

std::string format_rate_comment(long double rate, const std::string &label) {
  if (rate <= 0.0L) {
    return "";
  }

  if (label.find("cpu-cycles") != std::string::npos) {
    return format_decimal(rate / 1'000'000'000.0L, 6) + " GHz";
  }

  struct RateUnit {
    long double threshold;
    long double divisor;
    const char *suffix;
  };

  static constexpr RateUnit kUnits[] = {
      {1'000'000'000.0L, 1'000'000'000.0L, "G/sec"},
      {1'000'000.0L, 1'000'000.0L, "M/sec"},
      {1'000.0L, 1'000.0L, "K/sec"},
  };

  for (const auto &unit : kUnits) {
    if (rate >= unit.threshold) {
      return format_decimal(rate / unit.divisor, 3) + ' ' + unit.suffix;
    }
  }

  return format_decimal(rate, 3) + " /sec";
}

std::string build_comment(const CounterResult &result,
                          const std::unordered_map<std::string, const CounterResult *> &lookup,
                          long double fallback_seconds) {
  if (result.label.find("branch-misses") != std::string::npos) {
    auto it = lookup.find("hw-branch-instructions");
    if (it != lookup.end() && it->second->value > 0) {
      const long double miss_rate =
          static_cast<long double>(result.value) / static_cast<long double>(it->second->value) * 100.0L;
      return format_decimal(miss_rate, 6) + " miss rate";
    }
  }

  const long double seconds = result.time_enabled > 0 ? nanoseconds_to_seconds(result.time_enabled) : fallback_seconds;
  if (seconds <= 0.0L) {
    return "";
  }

  const long double rate = static_cast<long double>(result.value) / seconds;
  return format_rate_comment(rate, result.label);
}

std::string build_coverage_string(const CounterResult &result) {
  long double percent = 0.0L;
  if (result.time_enabled > 0) {
    percent = static_cast<long double>(result.time_running) / static_cast<long double>(result.time_enabled) * 100.0L;
  }

  std::ostringstream oss;
  oss << '(' << std::fixed << std::setprecision(2) << percent << "%)";
  return oss.str();
}
} // namespace

std::optional<std::vector<PerfHandle>> setup_perf_events(pid_t target_pid, const MonitorOptions &options) {
  std::vector<PerfHandle> handles;
  const std::size_t estimated_total = options.counters.size();
  std::size_t grouped_total = 0;
  for (const auto &group : options.counterGroups) {
    grouped_total += group.size();
  }
  handles.reserve(estimated_total + grouped_total);

  const auto open_counter = [&](const CounterConfig &counter, int group_fd,
                                int group_index) -> std::optional<PerfHandle> {
    PerfHandle handle;
    memset(&handle.attr, 0, sizeof(handle.attr));
    handle.attr.type = counter.type;
    handle.attr.size = sizeof(perf_event_attr);
    handle.attr.config = counter.config;
    handle.attr.disabled = 1;
    handle.attr.exclude_kernel = 1;
    handle.attr.exclude_hv = 1;
    handle.attr.inherit = 1;
    handle.attr.pinned = counter.pinned ? 1 : 0;
    handle.attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID;
    handle.label = counter.name;
    handle.groupIndex = group_index;

    const long fd = perf_event_open(&handle.attr, target_pid, -1, group_fd, 0);
    if (fd < std::numeric_limits<int>::min() || fd > std::numeric_limits<int>::max()) {
      std::cerr << "perf_event_open returned unexpected fd value for " << counter.name << std::endl;
      return std::nullopt;
    }
    handle.fd = static_cast<int>(fd);
    if (handle.fd < 0) {
      perror("perf_event_open");
      return std::nullopt;
    }
    return handle;
  };

  for (const CounterConfig &counter : options.counters) {
    auto handle = open_counter(counter, -1, 0);
    if (!handle) {
      return std::nullopt;
    }
    handles.push_back(std::move(*handle));
  }

  int next_group_index = 1;
  for (const auto &group : options.counterGroups) {
    const int current_group_index = next_group_index++;
    int leader_fd = -1;
    for (const CounterConfig &counter : group) {
      auto handle = open_counter(counter, leader_fd, current_group_index);
      if (!handle) {
        return std::nullopt;
      }
      if (leader_fd == -1) {
        leader_fd = handle->fd;
      }
      handles.push_back(std::move(*handle));
    }
  }

  return handles;
}

bool start_perf_counters(const std::vector<PerfHandle> &handles) {
  const auto perform = [](const PerfHandle &handle, unsigned long request, const char *message) {
    if (ioctl(handle.fd, request, 0) == -1) {
      perror(message);
      return false;
    }
    return true;
  };

  bool success = true;
  for (const PerfHandle &handle : handles) {
    success &= perform(handle, PERF_EVENT_IOC_RESET, "ioctl reset");
    success &= perform(handle, PERF_EVENT_IOC_ENABLE, "ioctl enable");
  }
  return success;
}

std::vector<CounterResult> stop_and_read_counters(const std::vector<PerfHandle> &handles) {
  std::vector<CounterResult> results;
  results.reserve(handles.size());

  struct PerfReadValues {
    uint64_t value;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t id;
  };

  const auto read_counter = [](const PerfHandle &handle, PerfReadValues &values) {
    uint8_t *buffer = reinterpret_cast<uint8_t *>(&values);
    size_t total_read = 0;
    while (total_read < sizeof(values)) {
      const ssize_t bytes_read = read(handle.fd, buffer + total_read, sizeof(values) - total_read);
      if (bytes_read < 0) {
        if (errno == EINTR) {
          continue;
        }
        perror("read");
        return false;
      }
      if (bytes_read == 0) {
        std::cerr << "Warning: unexpected EOF while reading counter for " << handle.label << std::endl;
        return false;
      }
      total_read += static_cast<size_t>(bytes_read);
    }
    return true;
  };

  for (const PerfHandle &handle : handles) {
    if (ioctl(handle.fd, PERF_EVENT_IOC_DISABLE, 0) == -1) {
      perror("ioctl disable");
    }

    PerfReadValues values{};
    if (!read_counter(handle, values)) {
      continue;
    }

    long long adjusted_value = static_cast<long long>(values.value);
    if (values.time_running > 0 && values.time_running != values.time_enabled) {
      const long double scale =
          static_cast<long double>(values.time_enabled) / static_cast<long double>(values.time_running);
      adjusted_value = static_cast<long long>(static_cast<long double>(values.value) * scale);
    }

    results.push_back(
        {handle.label, adjusted_value, values.time_enabled, values.time_running, values.id, handle.groupIndex});
  }

  return results;
}

int main(int argc, char *argv[]) {
  MonitorOptions options;
  std::vector<std::string> counter_names;
  std::vector<std::string> counter_group_specs;

  CLI::App cli_app{"Minimal wrapper around perf_event_open"};
  cli_app.footer(build_counter_help_footer());
  cli_app.allow_extras(true);

  cli_app.add_option("-p,--pid", options.targetPid, "Process ID to monitor (default: current process)");

  auto duration_option = cli_app.add_option("-d,--duration", options.durationSeconds, "Duration in seconds to monitor");
  duration_option->check(CLI::PositiveNumber);

  auto counters_option =
      cli_app.add_option("-c,--counters", counter_names, "Comma-separated perf counter names (software or hardware)");
  counters_option->delimiter(',');
  counters_option->expected(-1);

  cli_app.add_option("-g,--group", counter_group_specs,
                     "Counter group (comma-separated). May be repeated for multiple groups");

  CLI11_PARSE(cli_app, argc, argv);

  options.appCommand = cli_app.remaining();

  options.hasDuration = duration_option->count() > 0;

  if (!configure_counters(counter_names, options)) {
    return 1;
  }

  if (!configure_counter_groups(counter_group_specs, options)) {
    return 1;
  }

  if (options.counters.empty() && options.counterGroups.empty()) {
    options.counters.push_back({"sw-cpu-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK});
  }

  if (!options.appCommand.empty() && options.targetPid != 0) {
    std::cerr << "Error: cannot combine -p/--pid with a command passed after --" << std::endl;
    return 1;
  }

  pid_t child_pid = -1;
  if (!launch_target_command(options, child_pid)) {
    return 1;
  }

  if (child_pid > 0) {
    options.targetPid = child_pid;
    std::cout << "Monitoring child process (PID: " << child_pid << ")" << std::endl;
  } else if (options.targetPid == 0) {
    std::cout << "Monitoring current process (PID: " << getpid() << ")" << std::endl;
  } else {
    std::cout << "Monitoring PID: " << options.targetPid << std::endl;
  }

  if (options.hasDuration) {
    std::cout << "Duration: " << options.durationSeconds << " seconds" << std::endl;
  }

  const pid_t effective_pid = options.targetPid == 0 ? getpid() : options.targetPid;
  print_process_info(effective_pid);

  auto perf_handles = setup_perf_events(effective_pid, options);
  if (!perf_handles) {
    if (child_pid > 0) {
      terminate_child_process(child_pid);
    }
    return 1;
  }

  auto &handles = *perf_handles;

  if (!start_perf_counters(handles)) {
    if (child_pid > 0) {
      terminate_child_process(child_pid);
    }
    return 1;
  }

  if (child_pid > 0) {
    std::cout << "Resuming child process..." << std::endl;
    kill(child_pid, SIGCONT);

    int status = 0;
    if (options.hasDuration) {
      const ChildWaitResult wait_result = wait_for_child_with_timeout(child_pid, options.durationSeconds, status);
      if (wait_result == ChildWaitResult::Completed) {
        if (WIFEXITED(status)) {
          std::cout << "Command exited with status: " << WEXITSTATUS(status) << std::endl;
        }
      } else if (wait_result == ChildWaitResult::TimedOut) {
        std::cout << "Duration elapsed; terminating monitored command..." << std::endl;
        terminate_child_process(child_pid);
        if (waitpid(child_pid, &status, 0) == -1) {
          perror("waitpid");
        }
      } else {
        std::cerr << "Error while waiting for child process" << std::endl;
      }
    } else {
      if (waitpid(child_pid, &status, 0) == -1) {
        perror("waitpid");
      } else if (WIFEXITED(status)) {
        std::cout << "Command exited with status: " << WEXITSTATUS(status) << std::endl;
      }
    }
  } else if (options.hasDuration) {
    std::cout << "Monitoring for " << options.durationSeconds << " seconds..." << std::endl;
    sleep(options.durationSeconds);
  } else {
    std::cout << "No duration specified; capturing immediate snapshot." << std::endl;
  }

  const auto counter_results = stop_and_read_counters(handles);

  if (counter_results.empty()) {
    std::cout << "\nNo counter data collected." << std::endl;
    return 0;
  }

  std::unordered_map<std::string, const CounterResult *> lookup;
  for (const auto &result : counter_results) {
    lookup[result.label] = &result;
  }

  uint64_t max_time_enabled = 0;
  for (const auto &result : counter_results) {
    max_time_enabled = std::max(max_time_enabled, result.time_enabled);
  }
  if (max_time_enabled == 0 && options.hasDuration && options.durationSeconds > 0) {
    max_time_enabled = static_cast<uint64_t>(options.durationSeconds) * 1'000'000'000ULL;
  }

  const long double total_ms = static_cast<long double>(max_time_enabled) / 1'000'000.0L;
  const long double fallback_seconds = nanoseconds_to_seconds(max_time_enabled);

  struct DisplayRow {
    const CounterResult *result = nullptr;
    std::string group_text;
    std::string count_text;
    std::string comment;
    std::string coverage;
  };

  std::vector<DisplayRow> rows;
  rows.reserve(counter_results.size());
  for (const auto &result : counter_results) {
    DisplayRow row;
    row.result = &result;
    row.group_text = result.group_index > 0 ? std::to_string(result.group_index) : "-";
    row.count_text = format_with_commas(result.value);
    row.comment = build_comment(result, lookup, fallback_seconds);
    if (row.comment.empty()) {
      row.comment = "-";
    }
    row.coverage = build_coverage_string(result);
    rows.push_back(std::move(row));
  }

  size_t count_width = std::string("count").size();
  size_t name_width = std::string("name").size();
  size_t comment_width = std::string("comment").size();
  size_t coverage_width = std::string("coverage").size();
  size_t group_width = std::string("group").size();

  for (const auto &row : rows) {
    count_width = std::max(count_width, row.count_text.size());
    name_width = std::max(name_width, row.result->label.size());
    comment_width = std::max(comment_width, row.comment.size());
    coverage_width = std::max(coverage_width, row.coverage.size());
    group_width = std::max(group_width, row.group_text.size());
  }

  count_width += 4; // indent similar to perf output
  name_width += 2;
  comment_width += 2;
  group_width += 2;

  const std::string summary_label = options.hasDuration ? "Timeout exit" : "Measurement summary";
  std::ostringstream total_ms_stream;
  total_ms_stream << std::fixed << std::setprecision(0) << total_ms;
  std::cout << "\n" << summary_label << " (total " << total_ms_stream.str() << " ms)" << std::endl;

  std::cout << std::right << std::setw(static_cast<int>(count_width)) << "count" << "  " << std::left
            << std::setw(static_cast<int>(name_width)) << "name"
            << "| " << std::left << std::setw(static_cast<int>(comment_width)) << "comment"
            << "| " << std::left << std::setw(static_cast<int>(coverage_width)) << "coverage"
            << " | " << std::left << std::setw(static_cast<int>(group_width)) << "group" << std::endl;

  for (const auto &row : rows) {
    std::cout << std::right << std::setw(static_cast<int>(count_width)) << row.count_text << "  " << std::left
              << std::setw(static_cast<int>(name_width)) << row.result->label << "| " << std::left
              << std::setw(static_cast<int>(comment_width)) << row.comment << "| " << std::left
              << std::setw(static_cast<int>(coverage_width)) << row.coverage << " | " << std::left
              << std::setw(static_cast<int>(group_width)) << row.group_text << std::endl;
  }
  return 0;
}