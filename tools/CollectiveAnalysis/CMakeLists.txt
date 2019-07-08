cmake_minimum_required(VERSION 2.6)

add_executable(CollectiveAnalysis
    main.cpp
)

target_link_libraries(CollectiveAnalysis
    jitana
)

add_custom_target(CollectiveAnalysis-copy-files
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts
        ${CMAKE_CURRENT_BINARY_DIR}
)
add_dependencies(CollectiveAnalysis CollectiveAnalysis-copy-files)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/output/insn)
