#include "fs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

char *read_file(const char *file_path) {
	if (!file_path)
		return NULL;

	FILE *file = fopen(file_path, "rb");
	if (!file)
		return NULL;

	fseek(file, 0, SEEK_END);
	size_t size = ftell(file);
	fseek(file, 0, SEEK_SET);

	char *content = malloc(size + 1);
	if (!content) {
		fclose(file);
		return NULL;
	}

	fread(content, 1, size, file);
	content[size] = '\0';
	fclose(file);
	return content;
}
