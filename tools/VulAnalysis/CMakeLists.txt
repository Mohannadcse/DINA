cmake_minimum_required(VERSION 2.6)

find_package(Threads)

if(Threads_FOUND)
	add_executable(VulAnalysis
	    main.cpp
	)
	target_link_libraries(VulAnalysis
	    jitana
            ${CMAKE_THREAD_LIBS_INIT}
	)
	add_custom_target(VulAnalysis-copy-files
	    COMMAND ${CMAKE_COMMAND} -E copy_directory
		${CMAKE_CURRENT_SOURCE_DIR}/scripts
		${CMAKE_CURRENT_BINARY_DIR}
	)
	add_dependencies(VulAnalysis VulAnalysis-copy-files)

	file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/output/insn)
endif(Threads_FOUND)
