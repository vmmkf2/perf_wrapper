cmake_minimum_required(VERSION 3.14)
project(perf_wrapper VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)

FetchContent_Declare(
	CLI11
	GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
	GIT_TAG v2.3.2
)

FetchContent_MakeAvailable(CLI11)

# Add the executable
add_executable(perf_wrapper
	src/main.cpp
	src/helper.cpp
	src/counters.cpp)

target_link_libraries(perf_wrapper PRIVATE CLI11::CLI11)
