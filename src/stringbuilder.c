#include "stringbuilder.h"
#include <stdlib.h>
#include <string.h>

struct StringBuilder *sb_create(size_t initial_capacity) {
	if (initial_capacity == 0) {
		initial_capacity = STRINGBUILDER_INITIAL_CAPACITY;
	} else if (initial_capacity > STRINGBUILDER_MAX_CAPACITY) {
		initial_capacity = STRINGBUILDER_MAX_CAPACITY;
	}

	struct StringBuilder *sb = malloc(sizeof(struct StringBuilder));
	if (!sb)
		return NULL;

	sb->buffer = malloc(initial_capacity);
	if (!sb->buffer) {
		free(sb);
		return NULL;
	}

	sb->length = 0;
	sb->capacity = initial_capacity;
	sb->buffer[0] = '\0'; // Null-terminate the empty string
	return sb;
}

void sb_destroy(struct StringBuilder *sb) {
	if (sb) {
		free(sb->buffer);
		free(sb);
	}
}

void sb_append(struct StringBuilder *sb, const char *str) {
	if (!sb || !str)
		return;

	size_t str_len = strlen(str);
	sb_ensure_capacity(sb, str_len);

	memcpy(sb->buffer + sb->length, str,
		   str_len + 1); // +1 to copy null terminator
	sb->length += str_len;
}
void sb_append_char(struct StringBuilder *sb, char c) {
	if (!sb)
		return;

	sb_ensure_capacity(sb, 1);
	sb->buffer[sb->length++] = c;
	sb->buffer[sb->length] = '\0';
}

void sb_clear(struct StringBuilder *sb) {
	if (!sb)
		return;

	sb->length = 0;
	sb->buffer[0] = '\0';
}

char *sb_consume(struct StringBuilder *sb) {
	if (!sb)
		return NULL;

	char *result = sb->buffer;
	sb->buffer = malloc(STRINGBUILDER_INITIAL_CAPACITY);
	if (!sb->buffer) {
		// If allocation fails, restore the original buffer and return NULL
		sb->buffer = result;
		return NULL;
	}

	sb->length = 0;
	sb->capacity = STRINGBUILDER_INITIAL_CAPACITY;
	sb->buffer[0] = '\0';
	return result;
}

char *sb_to_string(struct StringBuilder *sb) {
	if (!sb)
		return NULL;

	char *result = malloc(sb->length + 1);
	if (!result)
		return NULL;

	memcpy(result, sb->buffer, sb->length + 1); // +1 to copy null terminator
	return result;
}

size_t sb_length(struct StringBuilder *sb) {
	if (!sb)
		return 0;
	return sb->length;
}

size_t sb_capacity(struct StringBuilder *sb) {
	if (!sb)
		return 0;
	return sb->capacity;
}

bool sb_is_empty(struct StringBuilder *sb) {
	if (!sb)
		return true;
	return sb->length == 0;
}

void sb_ensure_capacity(struct StringBuilder *sb, size_t additional_length) {
	if (!sb)
		return;

	size_t required_capacity =
		sb->length + additional_length + 1; // +1 for null terminator
	if (required_capacity > sb->capacity) {
		size_t new_capacity = sb->capacity;
		while (new_capacity < required_capacity) {
			new_capacity *= 2;
		}

		char *new_buffer = realloc(sb->buffer, new_capacity);
		if (!new_buffer) {
			// Handle allocation failure - could set an error flag or exit
			return;
		}

		sb->buffer = new_buffer;
		sb->capacity = new_capacity;
	}
}
