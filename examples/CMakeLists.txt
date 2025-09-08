cmake_minimum_required(VERSION 3.13)


function(add_examples)
    # Get all subdirectories in the examples folder
    file(GLOB EXAMPLE_DIRS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *)
    
    foreach(EXAMPLE_DIR ${EXAMPLE_DIRS})
        if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_DIR})
            # Check if the subdirectory contains C/C++ source files
            file(GLOB EXAMPLE_SOURCES 
                ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_DIR}/*.c
                ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_DIR}/*.cpp
                ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_DIR}/*.cxx
                ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_DIR}/*.cc
            )
            
            if(EXAMPLE_SOURCES)
                message(STATUS "Found example: ${EXAMPLE_DIR}")
                
                # Create executable for this example
                set(EXAMPLE_TARGET "example_${EXAMPLE_DIR}")
                add_executable(${EXAMPLE_TARGET} ${EXAMPLE_SOURCES})
                
                # Link against the server library
                target_link_libraries(${EXAMPLE_TARGET} PRIVATE server)
                
                # Include directories
                target_include_directories(${EXAMPLE_TARGET} PRIVATE 
                    ${CMAKE_SOURCE_DIR}/include
                )
                
                # Set output directory
                set_target_properties(${EXAMPLE_TARGET} PROPERTIES
                    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples
                )
                
                # Copy any additional files (like config files, data files, etc.)
                file(GLOB EXAMPLE_DATA_FILES 
                    ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_DIR}/*.txt
                    ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_DIR}/*.json
                    ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_DIR}/*.xml
                    ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_DIR}/*.cfg
                    ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_DIR}/*.conf
                )
                
                foreach(DATA_FILE ${EXAMPLE_DATA_FILES})
                    get_filename_component(FILE_NAME ${DATA_FILE} NAME)
                    configure_file(${DATA_FILE} 
                        ${CMAKE_BINARY_DIR}/examples/${FILE_NAME} 
                        COPYONLY
                    )
                endforeach()
                
                message(STATUS "  - Executable: ${EXAMPLE_TARGET}")
                message(STATUS "  - Sources: ${EXAMPLE_SOURCES}")
            endif()
        endif()
    endforeach()
endfunction()

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/examples)

add_examples()

# Print summary
message(STATUS "Examples configuration complete")
message(STATUS "Example executables will be built in: ${CMAKE_BINARY_DIR}/examples")
