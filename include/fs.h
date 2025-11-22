#pragma once

#include <stdbool.h>
#include <stddef.h>

// Common utility functions
size_t get_file_size(const char *file_path);
bool file_exists(const char *file_path);
char *read_file(const char *file_path);

int stream_file_to_socket(int sockfd, const char *file_path, size_t chunk_size);