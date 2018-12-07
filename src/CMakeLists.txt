add_subdirectory(test_elf)

add_executable(C4 c4.c hotpatchor/hotpatchor.h hotpatchor/hotpatchor.c)

add_executable(DECOY_C4 decoy_c4.c)
#target_compile_options(DECOY PRIVATE -fno-pie)
#target_link_libraries(DECOY -no-pie)

add_executable(C5 c5.c hotpatchor/hotpatchor.h hotpatchor/hotpatchor.c)

add_executable(DECOY_C5 decoy_c5.c)
target_link_libraries(DECOY_C5 pthread)