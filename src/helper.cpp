#include "helper.h"

#include <fstream>
#include <iostream>
#include <string>

namespace
{
    std::string trim_leading(const std::string &value)
    {
        const auto pos = value.find_first_not_of(" \t");
        if (pos == std::string::npos)
        {
            return "";
        }
        return value.substr(pos);
    }
} // namespace

void print_process_info(pid_t pid)
{
    std::cout << "\n=== Process Information ===" << std::endl;
    std::cout << "PID: " << pid << std::endl;

    std::string status_path = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream status_file(status_path);

    if (status_file.is_open())
    {
        std::string line;
        while (std::getline(status_file, line))
        {
            if (line.find("Name:") == 0)
            {
                std::cout << "Name: " << trim_leading(line.substr(5)) << std::endl;
            }
            else if (line.find("State:") == 0)
            {
                std::cout << "State: " << trim_leading(line.substr(6)) << std::endl;
            }
            else if (line.find("PPid:") == 0)
            {
                std::cout << "Parent PID: " << trim_leading(line.substr(5)) << std::endl;
            }
            else if (line.find("Threads:") == 0)
            {
                std::cout << "Threads: " << trim_leading(line.substr(8)) << std::endl;
            }
            else if (line.find("VmSize:") == 0)
            {
                std::cout << "Virtual Memory Size: " << trim_leading(line.substr(7)) << std::endl;
            }
            else if (line.find("VmRSS:") == 0)
            {
                std::cout << "Resident Set Size: " << trim_leading(line.substr(6)) << std::endl;
            }
        }
        status_file.close();
    }
    else
    {
        std::cerr << "Warning: Could not read process information from /proc/" << pid << "/status" << std::endl;
    }

    std::string cmdline_path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream cmdline_file(cmdline_path);

    if (cmdline_file.is_open())
    {
        std::string cmdline;
        std::getline(cmdline_file, cmdline);
        for (char &c : cmdline)
        {
            if (c == '\0')
            {
                c = ' ';
            }
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