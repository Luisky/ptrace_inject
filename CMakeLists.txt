cmake_minimum_required(VERSION 3.10)
project(SEL_TP C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE Debug)

add_executable(SEL_TP main.c hotpatchor.h hotpatchor.c)
add_executable(DECOY decoy.c)
#target_compile_options(DECOY PRIVATE -fno-pie)
#target_link_libraries(DECOY -no-pie)
add_executable(TEST_ELF test_elf.c)
target_link_libraries(TEST_ELF elf)