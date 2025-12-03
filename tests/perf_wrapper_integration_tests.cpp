#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <signal.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PERF_WRAPPER_BINARY
#error "PERF_WRAPPER_BINARY must be defined to point at the perf_wrapper executable"
#endif

struct CommandResult {
  int exit_code = -1;
  std::string output;
};

bool should_skip_due_to_permissions(const CommandResult &result) {
  if (result.exit_code == 0) {
    return false;
  }

  static const char *kPermissionHints[] = {
      "Operation not permitted",
      "Permission denied",
      "must be root",
  };

  for (const char *hint : kPermissionHints) {
    if (result.output.find(hint) != std::string::npos) {
      return true;
    }
  }
  return false;
}

CommandResult run_command(const std::string &command) {
  CommandResult result;
  const std::string command_with_redirect = command + " 2>&1";
  FILE *pipe = popen(command_with_redirect.c_str(), "r");
  REQUIRE_MESSAGE(pipe != nullptr, "Failed to run command: " << command);

  std::array<char, 256> buffer{};
  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    result.output += buffer.data();
  }

  const int status = pclose(pipe);
  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else {
    result.exit_code = status;
  }
  return result;
}

bool has_group_child_fd(const std::string &output) {
  const std::string needle = "group_fd=";
  std::size_t pos = output.find(needle);
  while (pos != std::string::npos) {
    pos += needle.size();
    if (pos < output.size() && output[pos] != '-') {
      return true;
    }
    pos = output.find(needle, pos);
  }
  return false;
}

class SleepProcess {
public:
  explicit SleepProcess(int seconds) {
    pid_ = fork();
    REQUIRE_MESSAGE(pid_ != -1, "fork failed when launching sleep helper");

    if (pid_ == 0) {
      const std::string duration = std::to_string(seconds);
      execlp("sleep", "sleep", duration.c_str(), nullptr);
      _exit(127);
    }
  }

  ~SleepProcess() {
    if (pid_ > 0) {
      kill(pid_, SIGKILL);
      waitpid(pid_, nullptr, 0);
    }
  }

  [[nodiscard]] pid_t id() const { return pid_; }

private:
  pid_t pid_ = -1;
};

TEST_CASE("profiles command passed after double dash") {
  const std::string command = std::string(PERF_WRAPPER_BINARY) + " -d 1 -c sw-cpu-clock -- /bin/true";

  const auto result = run_command(command);

  if (should_skip_due_to_permissions(result)) {
    WARN("perf_event_open not permitted in this environment - skipping test");
    return;
  }

  CHECK_EQ(result.exit_code, 0);
  CHECK(result.output.find("Monitoring child process") != std::string::npos);
  CHECK(result.output.find("Timeout exit (total") != std::string::npos);
  CHECK(result.output.find("| coverage") != std::string::npos);
  CHECK(result.output.find("| group") != std::string::npos);
  CHECK(result.output.find("| - ") != std::string::npos);
}

TEST_CASE("profiles an existing pid with -p") {
  SleepProcess sleeper(5);
  REQUIRE(sleeper.id() > 0);

  const std::string command =
      std::string(PERF_WRAPPER_BINARY) + " -d 1 -c sw-cpu-clock -p " + std::to_string(sleeper.id());

  const auto result = run_command(command);

  if (should_skip_due_to_permissions(result)) {
    WARN("perf_event_open not permitted in this environment - skipping test");
    return;
  }

  CHECK_EQ(result.exit_code, 0);
  CHECK(result.output.find("Monitoring PID:") != std::string::npos);
  CHECK(result.output.find("Timeout exit (total") != std::string::npos);
  CHECK(result.output.find("Duration: 1 seconds") != std::string::npos);
  CHECK(result.output.find("| coverage") != std::string::npos);
  CHECK(result.output.find("| group") != std::string::npos);
  CHECK(result.output.find("| - ") != std::string::npos);
}

TEST_CASE("supports grouped counters via -g") {
  const std::string command = std::string(PERF_WRAPPER_BINARY) + " -d 1 -g sw-cpu-clock,sw-task-clock -- /bin/true";

  const auto result = run_command(command);

  if (should_skip_due_to_permissions(result)) {
    WARN("perf_event_open not permitted in this environment - skipping test");
    return;
  }

  CHECK_EQ(result.exit_code, 0);
  CHECK(result.output.find("sw-cpu-clock") != std::string::npos);
  CHECK(result.output.find("sw-task-clock") != std::string::npos);
  CHECK(has_group_child_fd(result.output));
  CHECK(result.output.find("Timeout exit (total") != std::string::npos);
  CHECK(result.output.find("| 1 ") != std::string::npos);
}

TEST_CASE("mixes ungrouped and grouped counters") {
  const std::string command = std::string(PERF_WRAPPER_BINARY) +
                              " -d 1 -c sw-page-faults -g sw-context-switches,sw-cpu-migrations -- /bin/true";

  const auto result = run_command(command);

  if (should_skip_due_to_permissions(result)) {
    WARN("perf_event_open not permitted in this environment - skipping test");
    return;
  }

  CHECK_EQ(result.exit_code, 0);
  CHECK(result.output.find("sw-page-faults") != std::string::npos);
  CHECK(result.output.find("sw-cpu-migrations") != std::string::npos);
  CHECK(has_group_child_fd(result.output));
  CHECK(result.output.find("Timeout exit (total") != std::string::npos);
  CHECK(result.output.find("| 1 ") != std::string::npos);
}

TEST_CASE("supports pinned group leaders") {
  const std::string command =
      std::string(PERF_WRAPPER_BINARY) + " -d 1 -g sw-cpu-clock:P,sw-task-clock -- /bin/true";

  const auto result = run_command(command);

  if (should_skip_due_to_permissions(result)) {
    WARN("perf_event_open not permitted in this environment - skipping test");
    return;
  }

  CHECK_EQ(result.exit_code, 0);
  CHECK(result.output.find("sw-cpu-clock") != std::string::npos);
  CHECK(result.output.find("sw-task-clock") != std::string::npos);
  CHECK(result.output.find("| 1 ") != std::string::npos);
}

TEST_CASE("allows pinned counter specified later to become leader") {
  const std::string command =
      std::string(PERF_WRAPPER_BINARY) + " -d 1 -g sw-task-clock,sw-cpu-clock:P -- /bin/true";

  const auto result = run_command(command);

  if (should_skip_due_to_permissions(result)) {
    WARN("perf_event_open not permitted in this environment - skipping test");
    return;
  }

  CHECK_EQ(result.exit_code, 0);
  CHECK(result.output.find("sw-cpu-clock") != std::string::npos);
  CHECK(result.output.find("| 1 ") != std::string::npos);
}

TEST_CASE("supports explicit leader modifier") {
  const std::string command =
      std::string(PERF_WRAPPER_BINARY) + " -d 1 -g sw-task-clock:L,sw-cpu-clock -- /bin/true";

  const auto result = run_command(command);

  if (should_skip_due_to_permissions(result)) {
    WARN("perf_event_open not permitted in this environment - skipping test");
    return;
  }

  CHECK_EQ(result.exit_code, 0);
  CHECK(result.output.find("sw-task-clock") != std::string::npos);
  CHECK(result.output.find("| 1 ") != std::string::npos);
}

TEST_CASE("rejects multiple explicit leaders") {
  const std::string command =
      std::string(PERF_WRAPPER_BINARY) + " -d 1 -g sw-task-clock:L,sw-cpu-clock:L -- /bin/true";

  const auto result = run_command(command);

  if (should_skip_due_to_permissions(result)) {
    WARN("perf_event_open not permitted in this environment - skipping test");
    return;
  }

  CHECK_NE(result.exit_code, 0);
  CHECK(result.output.find("multiple explicit leaders") != std::string::npos);
}
