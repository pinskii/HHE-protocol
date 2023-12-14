cmake_minimum_required(VERSION 3.10) 

project(HHE-protocol)  

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SEAL_DIR src/seal_x64-windows/share/seal)
set(Microsoft.GSL_DIR src/ms-gsl_x64-windows/share/Microsoft.GSL)

find_package(SEAL 4.1.1 REQUIRED)

file(GLOB SOURCES "src/*.cpp")

add_executable(mything protocols/HHE-protocol.cpp)

target_link_libraries(HHE-protocol PRIVATE SEAL::seal)



