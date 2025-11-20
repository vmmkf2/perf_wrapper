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

struct MonitorOptions
{
    pid_t targetPid = 0;                 // 0 means current process
    int durationSeconds = 0;             // Optional duration for sampling existing processes
    bool hasDuration = false;            // Whether duration was explicitly provided
    std::vector<std::string> appCommand; // Command to spawn under measurement
};

enum class ParseResult
{
    Success,
    ShowHelp,
    Failure
};

static long perf_event_open(struct perf_event_attr *attr,
                            pid_t pid, int cpu, int group_fd,
                            unsigned long flags)
{
    // debug print of syscall parametrs
    std::cout << "perf_event_open called with pid=" << pid << ", cpu=" << cpu << ", group_fd=" << group_fd << ", flags=" << flags << std::endl;
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

void print_usage(const char *prog_name)
{
    std::cerr << "Usage: " << prog_name << " [-p PID] [-d DURATION] [-app COMMAND [ARGS...]]" << std::endl;
    std::cerr << "  -p PID       Process ID to monitor (default: current process)" << std::endl;
    std::cerr << "  -d DURATION  Duration in seconds to monitor (default: run test workload)" << std::endl;
    std::cerr << "  -app COMMAND Execute and monitor COMMAND with its arguments" << std::endl;
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

ParseResult parse_arguments(int argc, char *argv[], MonitorOptions &options)
{
    options = MonitorOptions{};
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-p") == 0)
        {
            if (i + 1 < argc)
            {
                options.targetPid = atoi(argv[++i]);
            }
            else
            {
                std::cerr << "Error: -p requires a PID argument" << std::endl;
                print_usage(argv[0]);
                return ParseResult::Failure;
            }
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            if (i + 1 < argc)
            {
                options.durationSeconds = atoi(argv[++i]);
                options.hasDuration = true;
                if (options.durationSeconds <= 0)
                {
                    std::cerr << "Error: duration must be positive" << std::endl;
                    return ParseResult::Failure;
                }
            }
            else
            {
                std::cerr << "Error: -d requires a duration argument" << std::endl;
                print_usage(argv[0]);
                return ParseResult::Failure;
            }
        }
        else if (strcmp(argv[i], "-app") == 0)
        {
            if (i + 1 < argc)
            {
                options.appCommand.assign(argv + i + 1, argv + argc);
                break; // Remaining args belong to the command
            }
            else
            {
                std::cerr << "Error: -app requires a command" << std::endl;
                print_usage(argv[0]);
                return ParseResult::Failure;
            }
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            return ParseResult::ShowHelp;
        }
        else
        {
            std::cerr << "Error: unknown option " << argv[i] << std::endl;
            print_usage(argv[0]);
            return ParseResult::Failure;
        }
    }

    return ParseResult::Success;
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
};

PerfHandle setup_perf_event(pid_t target_pid)
{
    PerfHandle handle;
    handle.attr.type = PERF_TYPE_SOFTWARE;
    handle.attr.size = sizeof(perf_event_attr);
    handle.attr.config = PERF_COUNT_SW_CPU_CLOCK;
    handle.attr.disabled = 1;
    handle.attr.exclude_kernel = 1;
    handle.attr.exclude_hv = 1;
    handle.attr.inherit = 1;

    handle.fd = perf_event_open(&handle.attr, target_pid, -1, -1, 0);
    return handle;
}

bool start_perf_counter(const PerfHandle &handle)
{
    if (handle.fd < 0)
    {
        return false;
    }
    if (ioctl(handle.fd, PERF_EVENT_IOC_RESET, 0) == -1)
    {
        perror("ioctl reset");
        return false;
    }
    if (ioctl(handle.fd, PERF_EVENT_IOC_ENABLE, 0) == -1)
    {
        perror("ioctl enable");
        return false;
    }
    return true;
}

long long stop_and_read_counter(const PerfHandle &handle)
{
    if (ioctl(handle.fd, PERF_EVENT_IOC_DISABLE, 0) == -1)
    {
        perror("ioctl disable");
    }

    long long count = 0;
    if (read(handle.fd, &count, sizeof(count)) < 0)
    {
        perror("read");
    }
    return count;
}

int main(int argc, char *argv[])
{
    MonitorOptions options;
    const ParseResult parse_result = parse_arguments(argc, argv, options);
    if (parse_result == ParseResult::ShowHelp)
    {
        return 0;
    }
    if (parse_result == ParseResult::Failure)
    {
        return 1;
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

    PerfHandle perf = setup_perf_event(effective_pid);
    if (perf.fd < 0)
    {
        perror("perf_event_open");
        if (child_pid > 0)
        {
            kill(child_pid, SIGKILL);
        }
        return 1;
    }

    if (!start_perf_counter(perf))
    {
        close(perf.fd);
        if (child_pid > 0)
        {
            kill(child_pid, SIGKILL);
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

    const long long instructions = stop_and_read_counter(perf);
    close(perf.fd);

    std::cout << "Instructions: " << instructions << std::endl;
    return 0;
}