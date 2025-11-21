#pragma once

#include <sys/types.h>
#include <string>

void print_process_info(pid_t pid);
std::string format_with_commas(long long value);
