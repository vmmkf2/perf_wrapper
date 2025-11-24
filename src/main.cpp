#include <CLI/CLI.hpp>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <linux/perf_event.h>
#include <optional>
#include <signal.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "counters.h"
#include "helper.h"

struct MonitorOptions {
  pid_t targetPid = 0;                 // 0 means current process
  int durationSeconds = 0;             // Optional duration for sampling existing processes
  bool hasDuration = false;            // Whether duration was explicitly provided
  std::vector<std::string> appCommand; // Command to spawn under measurement
  std::vector<CounterConfig> counters = {{"sw-cpu-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK}};
};

bool configure_counters(const std::vector<std::string> &names, MonitorOptions &options) {
  if (!names.empty()) {
    std::vector<CounterConfig> configured;
    configured.reserve(names.size());

    for (const auto &name : names) {
      if (!add_counter_by_name(name, configured)) {
        std::cerr << "Error: unknown counter '" << name << "'" << std::endl;
        return false;
      }
    }

    if (configured.empty()) {
      std::cerr << "Error: no counters specified" << std::endl;
      return false;
    }

    options.counters = std::move(configured);
    return true;
  }

  if (options.counters.empty()) {
    options.counters.push_back({"sw-cpu-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK});
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

  PerfHandle() = default;
  PerfHandle(const PerfHandle &) = delete;
  PerfHandle &operator=(const PerfHandle &) = delete;

  PerfHandle(PerfHandle &&other) noexcept : attr(other.attr), fd(other.fd), label(std::move(other.label)) {
    other.fd = -1;
    other.attr = perf_event_attr{};
  }

  PerfHandle &operator=(PerfHandle &&other) noexcept {
    if (this != &other) {
      close_fd();
      attr = other.attr;
      fd = other.fd;
      label = std::move(other.label);
      other.fd = -1;
      other.attr = perf_event_attr{};
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
};

std::optional<std::vector<PerfHandle>> setup_perf_events(pid_t target_pid, const std::vector<CounterConfig> &counters) {
  std::vector<PerfHandle> handles;
  handles.reserve(counters.size());

  for (const CounterConfig &counter : counters) {
    PerfHandle handle;
    memset(&handle.attr, 0, sizeof(handle.attr));
    handle.attr.type = counter.type;
    handle.attr.size = sizeof(perf_event_attr);
    handle.attr.config = counter.config;
    handle.attr.disabled = 1;
    handle.attr.exclude_kernel = 1;
    handle.attr.exclude_hv = 1;
    handle.attr.inherit = 1;
    handle.attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID;
    handle.label = counter.name;

    const long fd = perf_event_open(&handle.attr, target_pid, -1, -1, 0);
    if (fd < std::numeric_limits<int>::min() || fd > std::numeric_limits<int>::max()) {
      std::cerr << "perf_event_open returned unexpected fd value for " << counter.name << std::endl;
      return std::nullopt;
    }
    handle.fd = static_cast<int>(fd);
    if (handle.fd < 0) {
      perror("perf_event_open");
      return std::nullopt;
    }

    handles.push_back(std::move(handle));
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

    results.push_back({handle.label, adjusted_value, values.time_enabled, values.time_running, values.id});
  }

  return results;
}

int main(int argc, char *argv[]) {
  MonitorOptions options;
  std::vector<std::string> counter_names;

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

  CLI11_PARSE(cli_app, argc, argv);

  options.appCommand = cli_app.remaining();

  options.hasDuration = duration_option->count() > 0;

  if (!configure_counters(counter_names, options)) {
    return 1;
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

  auto perf_handles = setup_perf_events(effective_pid, options.counters);
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

  std::cout << "\n=== Counter Results ===" << std::endl;
  for (const auto &result : counter_results) {
    std::cout << result.label << ": " << format_with_commas(result.value);
    if (result.time_running > 0 && result.time_running != result.time_enabled) {
      std::cout << " (enabled=" << result.time_enabled << ", running=" << result.time_running << ")";
    }
    std::cout << std::endl;
  }
  return 0;
}