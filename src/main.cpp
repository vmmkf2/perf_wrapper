#include <iostream>

int main(int argc, char* argv[]) {
    std::cout << "perf_wrapper - A tool to learn perf_events" << std::endl;
    
    if (argc > 1) {
        std::cout << "Arguments provided: " << argc - 1 << std::endl;
        for (int i = 1; i < argc; i++) {
            std::cout << "  " << i << ": " << argv[i] << std::endl;
        }
    }
    
    return 0;
}
