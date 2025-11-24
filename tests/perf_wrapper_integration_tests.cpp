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

  CHECK_EQ(result.exit_code, 0);
  CHECK(result.output.find("Monitoring child process") != std::string::npos);
  CHECK(result.output.find("=== Counter Results ===") != std::string::npos);
}

TEST_CASE("profiles an existing pid with -p") {
  SleepProcess sleeper(5);
  REQUIRE(sleeper.id() > 0);

  const std::string command =
      std::string(PERF_WRAPPER_BINARY) + " -d 1 -c sw-cpu-clock -p " + std::to_string(sleeper.id());

  const auto result = run_command(command);

  CHECK_EQ(result.exit_code, 0);
  CHECK(result.output.find("Monitoring PID:") != std::string::npos);
  CHECK(result.output.find("=== Counter Results ===") != std::string::npos);
  CHECK(result.output.find("Duration: 1 seconds") != std::string::npos);
}
