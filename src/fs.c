#define _GNU_SOURCE
#include "fs.h"
#include "arena.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int stream_file_to_socket(int sockfd, const char *file_path,
						  size_t chunk_size) {
	int fd = open(file_path, O_RDONLY);
	if (fd < 0)
		return -1;
	struct stat st;
	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}
	off_t file_size = st.st_size;
	off_t offset = 0;

	while (offset < file_size) {
		ssize_t sent = sendfile(sockfd, fd, &offset, file_size - offset);
		if (sent <= 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
	}
	close(fd);
	return 0;
}

size_t get_file_size(const char *file_path) {
	if (!file_path)
		return 0;
	FILE *file = fopen(file_path, "rb");
	if (!file)
		return 0;

	fseek(file, 0, SEEK_END);
	size_t size = ftell(file);
	fclose(file);
	return size;
}

bool file_exists(const char *file_path) {
	if (!file_path)
		return false;
	FILE *file = fopen(file_path, "r");
	if (file) {
		fclose(file);
		return true;
	}
	return false;
}

char *fs_read_file(Arena *arena, const char *file_path) {
	if (!file_path)
		return NULL;

	FILE *file = fopen(file_path, "rb");
	if (!file)
		return NULL;

	fseek(file, 0, SEEK_END);
	size_t size = ftell(file);
	fseek(file, 0, SEEK_SET);

	char *content = arena_alloc(arena, size + 1);
	if (!content) {
		fclose(file);
		return NULL;
	}

	fread(content, 1, size, file);
	content[size] = '\0';
	fclose(file);
	return content;
}

// Memory-mapped file structure for efficient large file handling
struct MappedFile *mmap_file(const char *file_path) {
	if (!file_path)
		return NULL;

	int fd = open(file_path, O_RDONLY);
	if (fd < 0)
		return NULL;

	struct stat st;
	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}

	size_t size = st.st_size;
	if (size == 0) {
		close(fd);
		return NULL;
	}

	void *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd); // fd can be closed after mmap

	if (data == MAP_FAILED)
		return NULL;

	// Advise kernel for sequential access (good for serving files)
	madvise(data, size, MADV_SEQUENTIAL);

	struct MappedFile *mf = malloc(sizeof(struct MappedFile));
	if (!mf) {
		munmap(data, size);
		return NULL;
	}

	mf->data = data;
	mf->size = size;
	return mf;
}

void munmap_file(struct MappedFile *mf) {
	if (!mf)
		return;
	if (mf->data && mf->size > 0)
		munmap(mf->data, mf->size);
	free(mf);
}

// Read file using mmap - returns a malloc'd copy of the file content
// More efficient for large files due to lazy loading
char *read_file_mmap(const char *file_path) {
	struct MappedFile *mf = mmap_file(file_path);
	if (!mf)
		return NULL;

	char *content = malloc(mf->size + 1);
	if (!content) {
		munmap_file(mf);
		return NULL;
	}

	memcpy(content, mf->data, mf->size);
	content[mf->size] = '\0';

	munmap_file(mf);
	return content;
}

// Stream file to socket using mmap - zero-copy when possible
int stream_file_mmap(int sockfd, const char *file_path) {
	struct MappedFile *mf = mmap_file(file_path);
	if (!mf)
		return -1;

	size_t total_sent = 0;
	while (total_sent < mf->size) {
		ssize_t sent =
			write(sockfd, (char *)mf->data + total_sent, mf->size - total_sent);
		if (sent < 0) {
			if (errno == EINTR)
				continue;
			munmap_file(mf);
			return -1;
		}
		total_sent += sent;
	}

	munmap_file(mf);
	return 0;
}
