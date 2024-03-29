cmake_minimum_required(VERSION 2.6)

find_package(OpenGL)
find_package(GLUT)
find_package(Threads)

if(OPENGL_FOUND AND GLUT_FOUND AND Threads_FOUND)
    add_executable(IncrementalAnalysis
        main.cpp
    )
    target_link_libraries(IncrementalAnalysis
        jitana
	${Boost_LIBRARIES}
        ${OPENGL_LIBRARY}
        ${GLUT_LIBRARY}
        ${CMAKE_THREAD_LIBS_INIT}
    )
    add_custom_target(IncrementalAnalysis-copy-files
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts
            ${CMAKE_CURRENT_BINARY_DIR}
    )
    add_dependencies(IncrementalAnalysis IncrementalAnalysis-copy-files)

    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/output/insn)
endif(OPENGL_FOUND AND GLUT_FOUND AND Threads_FOUND)
