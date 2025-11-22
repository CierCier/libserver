cmake_minimum_required(VERSION 3.13)

project(server)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

FIND_PACKAGE(Threads REQUIRED)
#FIND_PACKAGE(PkgConfig REQUIRED)


#pkg_check_modules( deps REQUIRED IMPORTED_TARGET)


file(GLOB_RECURSE SERVER_SRC src/*.c)


add_library(server SHARED ${SERVER_SRC})
target_compile_definitions(server PRIVATE _POSIX_C_SOURCE=200112L)
target_compile_definitions(server PRIVATE _MIN_THREAD_COUNT=64)
target_compile_options(server PRIVATE -pthread)



target_include_directories(server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)



include(CTest)
enable_testing()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})


# TARGET_LINK_LIBRARIES(server PkgConfig::deps)
TARGET_LINK_LIBRARIES(server pthread ${CMAKE_THREAD_LIBS_INIT})

# Add examples subdirectory
add_subdirectory(examples)

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
