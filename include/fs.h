#pragma once

#include <stdbool.h>
#include <stddef.h>

struct Arena;

// Memory-mapped file structure
struct MappedFile {
	void *data;	 // Pointer to mapped memory region
	size_t size; // Size of the mapped region
};

// Common utility functions
size_t get_file_size(const char *file_path);
bool file_exists(const char *file_path);
char *fs_read_file(struct Arena *arena, const char *file_path);

int stream_file_to_socket(int sockfd, const char *file_path, size_t chunk_size);

// Memory-mapped file operations (efficient for large files)
struct MappedFile *mmap_file(const char *file_path);
void munmap_file(struct MappedFile *mf);
char *read_file_mmap(const char *file_path);
int stream_file_mmap(int sockfd, const char *file_path);