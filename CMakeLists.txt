cmake_minimum_required(VERSION 3.10)  # Minimum version of CMake required

project(HHE-protocol)  # Replace YourProjectName with the actual name of your project

# Set C++ standard (optional but recommended)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SEAL 4.1.1 REQUIRED)

# Add your source files
file(GLOB SOURCES "src/*.cpp")

# Add executable target
add_executable(mything protocols/mything.cpp)

# Specify additional include directories if needed
target_include_directories(YourExecutable PRIVATE include)

# Specify additional libraries if needed
# target_link_libraries(YourExecutable PRIVATE YourLibrary)
target_link_libraries(mything PRIVATE SEAL::seal)

# Specify compiler options if needed
# target_compile_options(YourExecutable PRIVATE -Wall -Wextra)

# Specify output directory for the executable (optional)
set_target_properties(YourExecutable PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# You can add more configuration options as needed
