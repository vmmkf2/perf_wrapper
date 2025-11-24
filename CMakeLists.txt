cmake_minimum_required(VERSION 3.14)
project(perf_wrapper VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)
include(CTest)
enable_testing()

FetchContent_Declare(
	CLI11
	GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
	GIT_TAG v2.3.2
)

FetchContent_MakeAvailable(CLI11)

FetchContent_Declare(
	doctest
	GIT_REPOSITORY https://github.com/doctest/doctest.git
	GIT_TAG v2.4.11
)

FetchContent_MakeAvailable(doctest)

# Add the executable
add_executable(perf_wrapper
	src/main.cpp
	src/helper.cpp
	src/counters.cpp)

target_link_libraries(perf_wrapper PRIVATE CLI11::CLI11)

set(COMMON_WARNING_FLAGS)
if (MSVC)
	list(APPEND COMMON_WARNING_FLAGS /W4 /WX)
else()
	list(APPEND COMMON_WARNING_FLAGS -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
endif()

target_compile_options(perf_wrapper PRIVATE ${COMMON_WARNING_FLAGS})

add_executable(perf_wrapper_tests
	tests/perf_wrapper_integration_tests.cpp)

target_link_libraries(perf_wrapper_tests PRIVATE doctest::doctest)
target_compile_options(perf_wrapper_tests PRIVATE ${COMMON_WARNING_FLAGS})
target_compile_definitions(perf_wrapper_tests PRIVATE PERF_WRAPPER_BINARY="$<TARGET_FILE:perf_wrapper>")
add_dependencies(perf_wrapper_tests perf_wrapper)

add_test(NAME perf_wrapper_integration COMMAND perf_wrapper_tests)
