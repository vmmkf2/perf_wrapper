#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <vector>
#include <fstream>
#include <string>
#include <chrono>
#include <thread>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <cstdint>
#include <CLI/CLI.hpp>

struct CounterConfig
{
    std::string name;
    uint32_t type;
    uint64_t config;
};

struct MonitorOptions
{
    pid_t targetPid = 0;                 // 0 means current process
    int durationSeconds = 0;             // Optional duration for sampling existing processes
    bool hasDuration = false;            // Whether duration was explicitly provided
    std::vector<std::string> appCommand; // Command to spawn under measurement
    std::vector<CounterConfig> counters = {{"sw-cpu-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK}};
};

struct CounterNameEntry
{
    const char *name;
    uint32_t type;
    uint64_t config;
};

static const CounterNameEntry kSupportedCounters[] = {
    // Software counters
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
    // Hardware counters
    {"hw-cpu-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"hw-instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"hw-cache-references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES},
    {"hw-cache-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES},
    {"hw-branch-instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"hw-branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"hw-bus-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BUS_CYCLES},
    {"hw-stalled-cycles-frontend", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND},
    {"hw-stalled-cycles-backend", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND},
    {"hw-ref-cpu-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_REF_CPU_CYCLES}};

std::string list_counters_by_type(uint32_t type)
{
    std::ostringstream oss;
    bool first = true;
    for (const auto &entry : kSupportedCounters)
    {
        if (entry.type != type)
        {
            continue;
        }
        if (!first)
        {
            oss << ", ";
        }
        oss << entry.name;
        first = false;
    }
    if (first)
    {
        oss << "(none)";
    }
    return oss.str();
}

std::string build_counter_help_footer()
{
    std::ostringstream oss;
    oss << "\nSoftware counters: " << list_counters_by_type(PERF_TYPE_SOFTWARE)
        << "\nHardware counters: " << list_counters_by_type(PERF_TYPE_HARDWARE);
    return oss.str();
}

std::string trim_copy(const std::string &value)
{
    const auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char ch)
                                        { return std::isspace(ch); });
    const auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch)
                                      { return std::isspace(ch); })
                         .base();
    if (begin >= end)
    {
        return "";
    }
    return std::string(begin, end);
}

std::string to_lower_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch)
                   { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool add_counter_by_name(const std::string &name, MonitorOptions &options)
{
    const std::string normalized = to_lower_copy(trim_copy(name));
    if (normalized.empty())
    {
        return false;
    }

    for (const auto &entry : kSupportedCounters)
    {
        if (normalized == entry.name)
        {
            options.counters.push_back({entry.name, entry.type, entry.config});
            return true;
        }
    }
    return false;
}

static long perf_event_open(struct perf_event_attr *attr,
                            pid_t pid, int cpu, int group_fd,
                            unsigned long flags)
{
    // debug print of syscall parametrs
    std::cout << "perf_event_open called with pid=" << pid << ", cpu=" << cpu << ", group_fd=" << group_fd << ", flags=" << flags << std::endl;
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

void print_process_info(pid_t pid)
{
    std::cout << "\n=== Process Information ===" << std::endl;
    std::cout << "PID: " << pid << std::endl;

    // Read /proc/[pid]/status for process information
    std::string status_path = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream status_file(status_path);

    if (status_file.is_open())
    {
        std::string line;
        while (std::getline(status_file, line))
        {
            // Extract relevant fields
            if (line.find("Name:") == 0)
            {
                std::cout << "Process " << line.substr(5) << std::endl;
            }
            else if (line.find("State:") == 0)
            {
                std::cout << "" << line.substr(6) << std::endl;
            }
            else if (line.find("PPid:") == 0)
            {
                std::cout << "Parent PID: " << line.substr(5) << std::endl;
            }
            else if (line.find("Threads:") == 0)
            {
                std::cout << "" << line.substr(8) << std::endl;
            }
            else if (line.find("VmSize:") == 0)
            {
                std::cout << "Virtual Memory Size: " << line.substr(7) << std::endl;
            }
            else if (line.find("VmRSS:") == 0)
            {
                std::cout << "Resident Set Size: " << line.substr(6) << std::endl;
            }
        }
        status_file.close();
    }
    else
    {
        std::cerr << "Warning: Could not read process information from /proc/" << pid << "/status" << std::endl;
    }

    // Read command line
    std::string cmdline_path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream cmdline_file(cmdline_path);

    if (cmdline_file.is_open())
    {
        std::string cmdline;
        std::getline(cmdline_file, cmdline);
        // Replace null bytes with spaces for display
        for (char &c : cmdline)
        {
            if (c == '\0')
                c = ' ';
        }
        if (!cmdline.empty())
        {
            std::cout << "Command: " << cmdline << std::endl;
        }
        cmdline_file.close();
    }

    std::cout << "===========================\n"
              << std::endl;
}

std::vector<char *> build_exec_argv(const std::vector<std::string> &command)
{
    std::vector<char *> argv;
    argv.reserve(command.size() + 1);
    for (const std::string &arg : command)
    {
        argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);
    return argv;
}

bool wait_for_child_stop(pid_t child_pid)
{
    int status = 0;
    if (waitpid(child_pid, &status, WUNTRACED) == -1)
    {
        perror("waitpid");
        return false;
    }
    if (!WIFSTOPPED(status))
    {
        std::cerr << "Error: child process did not stop as expected" << std::endl;
        return false;
    }
    return true;
}

enum class ChildWaitResult
{
    Completed,
    TimedOut,
    Error
};

ChildWaitResult wait_for_child_with_timeout(pid_t child_pid, int timeoutSeconds, int &status)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSeconds);
    while (true)
    {
        pid_t result = waitpid(child_pid, &status, WNOHANG);
        if (result == -1)
        {
            perror("waitpid");
            return ChildWaitResult::Error;
        }
        if (result > 0)
        {
            return ChildWaitResult::Completed;
        }

        if (std::chrono::steady_clock::now() >= deadline)
        {
            return ChildWaitResult::TimedOut;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void terminate_child_process(pid_t child_pid)
{
    if (child_pid <= 0)
    {
        return;
    }

    if (kill(child_pid, SIGKILL) == -1)
    {
        perror("kill");
    }
}

std::string format_with_commas(long long value)
{
    std::string digits = std::to_string(value);
    const std::size_t prefix = digits[0] == '-' ? 1 : 0;

    if (digits.size() - prefix > 3)
    {
        for (int i = static_cast<int>(digits.size()) - 3; i > static_cast<int>(prefix); i -= 3)
        {
            digits.insert(static_cast<std::size_t>(i), ",");
        }
    }

    return digits;
}

bool launch_target_command(const MonitorOptions &options, pid_t &child_pid)
{
    if (options.appCommand.empty())
    {
        child_pid = -1;
        return true;
    }

    std::cout << "Running command: " << options.appCommand.front();
    for (size_t i = 1; i < options.appCommand.size(); i++)
    {
        std::cout << " " << options.appCommand[i];
    }
    std::cout << std::endl;

    child_pid = fork();
    if (child_pid == -1)
    {
        perror("fork");
        return false;
    }

    if (child_pid == 0)
    {
        // Child process waits for parent to configure perf
        raise(SIGSTOP);
        std::vector<char *> exec_args = build_exec_argv(options.appCommand);
        execvp(exec_args[0], exec_args.data());
        perror("execvp");
        _exit(1);
    }

    if (!wait_for_child_stop(child_pid))
    {
        kill(child_pid, SIGKILL);
        waitpid(child_pid, nullptr, 0);
        return false;
    }

    return true;
}

struct PerfHandle
{
    perf_event_attr attr{};
    int fd = -1;
    std::string label;
};

struct CounterResult
{
    std::string label;
    long long value = 0;
    uint64_t time_enabled = 0;
    uint64_t time_running = 0;
    uint64_t id = 0;
};

bool setup_perf_events(pid_t target_pid, const std::vector<CounterConfig> &counters, std::vector<PerfHandle> &handles)
{
    handles.clear();
    handles.reserve(counters.size());

    for (const CounterConfig &counter : counters)
    {
        PerfHandle handle;
        handle.attr.type = counter.type;
        handle.attr.size = sizeof(perf_event_attr);
        handle.attr.config = counter.config;
        handle.attr.disabled = 1;
        handle.attr.exclude_kernel = 1;
        handle.attr.exclude_hv = 1;
        handle.attr.inherit = 1;
        handle.attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
                      PERF_FORMAT_TOTAL_TIME_RUNNING |
                      PERF_FORMAT_ID;
        handle.label = counter.name;

        handle.fd = perf_event_open(&handle.attr, target_pid, -1, -1, 0);
        if (handle.fd < 0)
        {
            perror("perf_event_open");
            for (PerfHandle &opened : handles)
            {
                if (opened.fd >= 0)
                {
                    close(opened.fd);
                }
            }
            handles.clear();
            return false;
        }

        handles.push_back(std::move(handle));
    }

    return true;
}

bool start_perf_counters(const std::vector<PerfHandle> &handles)
{
    bool success = true;
    for (const PerfHandle &handle : handles)
    {
        if (ioctl(handle.fd, PERF_EVENT_IOC_RESET, 0) == -1)
        {
            perror("ioctl reset");
            success = false;
        }
        if (ioctl(handle.fd, PERF_EVENT_IOC_ENABLE, 0) == -1)
        {
            perror("ioctl enable");
            success = false;
        }
    }
    return success;
}

std::vector<CounterResult> stop_and_read_counters(const std::vector<PerfHandle> &handles)
{
    std::vector<CounterResult> results;
    results.reserve(handles.size());

    struct PerfReadValues
    {
        uint64_t value;
        uint64_t time_enabled;
        uint64_t time_running;
        uint64_t id;
    };

    for (const PerfHandle &handle : handles)
    {
        if (ioctl(handle.fd, PERF_EVENT_IOC_DISABLE, 0) == -1)
        {
            perror("ioctl disable");
        }

        PerfReadValues values{};
        const ssize_t bytes_read = read(handle.fd, &values, sizeof(values));
        if (bytes_read < 0)
        {
            perror("read");
            continue;
        }
        if (static_cast<size_t>(bytes_read) != sizeof(values))
        {
            std::cerr << "Warning: unexpected perf read size for " << handle.label << std::endl;
            continue;
        }

        long long adjusted_value = static_cast<long long>(values.value);
        if (values.time_running > 0 && values.time_running != values.time_enabled)
        {
            const long double scale = static_cast<long double>(values.time_enabled) /
                                      static_cast<long double>(values.time_running);
            adjusted_value = static_cast<long long>(static_cast<long double>(values.value) * scale);
        }

        results.push_back({handle.label, adjusted_value, values.time_enabled, values.time_running, values.id});
    }

    return results;
}

void close_perf_handles(std::vector<PerfHandle> &handles)
{
    for (PerfHandle &handle : handles)
    {
        if (handle.fd >= 0)
        {
            close(handle.fd);
            handle.fd = -1;
        }
    }
    handles.clear();
}

int main(int argc, char *argv[])
{
    MonitorOptions options;
    std::vector<std::string> counter_names;

    CLI::App cli_app{"Minimal wrapper around perf_event_open"};
    cli_app.footer(build_counter_help_footer());
    cli_app.allow_extras(true);

    cli_app.add_option("-p,--pid", options.targetPid, "Process ID to monitor (default: current process)");

    auto duration_option = cli_app.add_option("-d,--duration", options.durationSeconds, "Duration in seconds to monitor");
    duration_option->check(CLI::PositiveNumber);

    auto counters_option = cli_app.add_option("-c,--counters", counter_names, "Comma-separated perf counter names (software or hardware)");
    counters_option->delimiter(',');
    counters_option->expected(-1);

    CLI11_PARSE(cli_app, argc, argv);

    options.appCommand = cli_app.remaining();

    options.hasDuration = duration_option->count() > 0;

    if (!counter_names.empty())
    {
        options.counters.clear();
        for (const auto &name : counter_names)
        {
            if (!add_counter_by_name(name, options))
            {
                std::cerr << "Error: unknown counter '" << name << "'" << std::endl;
                return 1;
            }
        }
        if (options.counters.empty())
        {
            std::cerr << "Error: no counters specified" << std::endl;
            return 1;
        }
    }

    if (options.counters.empty())
    {
        options.counters.push_back({"sw-cpu-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK});
    }

    pid_t child_pid = -1;
    if (!launch_target_command(options, child_pid))
    {
        return 1;
    }

    if (child_pid > 0)
    {
        options.targetPid = child_pid;
        std::cout << "Monitoring child process (PID: " << child_pid << ")" << std::endl;
    }
    else if (options.targetPid == 0)
    {
        std::cout << "Monitoring current process (PID: " << getpid() << ")" << std::endl;
    }
    else
    {
        std::cout << "Monitoring PID: " << options.targetPid << std::endl;
    }

    if (options.hasDuration)
    {
        std::cout << "Duration: " << options.durationSeconds << " seconds" << std::endl;
    }

    const pid_t effective_pid = options.targetPid == 0 ? getpid() : options.targetPid;
    print_process_info(effective_pid);

    std::vector<PerfHandle> perf_handles;
    if (!setup_perf_events(effective_pid, options.counters, perf_handles))
    {
        if (child_pid > 0)
        {
            terminate_child_process(child_pid);
        }
        return 1;
    }

    if (!start_perf_counters(perf_handles))
    {
        close_perf_handles(perf_handles);
        if (child_pid > 0)
        {
            terminate_child_process(child_pid);
        }
        return 1;
    }

    if (child_pid > 0)
    {
        std::cout << "Resuming child process..." << std::endl;
        kill(child_pid, SIGCONT);

        int status = 0;
        if (options.hasDuration)
        {
            const ChildWaitResult wait_result = wait_for_child_with_timeout(child_pid, options.durationSeconds, status);
            if (wait_result == ChildWaitResult::Completed)
            {
                if (WIFEXITED(status))
                {
                    std::cout << "Command exited with status: " << WEXITSTATUS(status) << std::endl;
                }
            }
            else if (wait_result == ChildWaitResult::TimedOut)
            {
                std::cout << "Duration elapsed; terminating monitored command..." << std::endl;
                terminate_child_process(child_pid);
                if (waitpid(child_pid, &status, 0) == -1)
                {
                    perror("waitpid");
                }
            }
            else
            {
                std::cerr << "Error while waiting for child process" << std::endl;
            }
        }
        else
        {
            if (waitpid(child_pid, &status, 0) == -1)
            {
                perror("waitpid");
            }
            else if (WIFEXITED(status))
            {
                std::cout << "Command exited with status: " << WEXITSTATUS(status) << std::endl;
            }
        }
    }
    else if (options.hasDuration)
    {
        std::cout << "Monitoring for " << options.durationSeconds << " seconds..." << std::endl;
        sleep(options.durationSeconds);
    }
    else
    {
        std::cout << "No duration specified; capturing immediate snapshot." << std::endl;
    }

    const auto counter_results = stop_and_read_counters(perf_handles);
    close_perf_handles(perf_handles);

    std::cout << "\n=== Counter Results ===" << std::endl;
    for (const auto &result : counter_results)
    {
        std::cout << result.label << ": " << format_with_commas(result.value);
        if (result.time_running > 0 && result.time_running != result.time_enabled)
        {
            std::cout << " (enabled=" << result.time_enabled
                      << ", running=" << result.time_running << ")";
        }
        std::cout << std::endl;
    }
    return 0;
}