cmake_minimum_required(VERSION 3.10)
project(perf_wrapper VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable
add_executable(perf_wrapper src/main.cpp)
