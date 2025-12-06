#include "stringbuilder.h"
#include "arena.h"
#include <stdlib.h>
#include <string.h>

StringBuilder *sb_create(struct Arena *arena, size_t initial_capacity) {
	if (initial_capacity == 0) {
		initial_capacity = STRINGBUILDER_INITIAL_CAPACITY;
	}

	StringBuilder *sb;
	if (arena) {
		sb = arena_alloc(arena, sizeof(StringBuilder));
	} else {
		sb = malloc(sizeof(StringBuilder));
	}

	if (!sb) {
		return NULL;
	}

	sb->arena = arena;

	if (arena) {
		sb->buffer = arena_alloc(arena, initial_capacity);
	} else {
		sb->buffer = malloc(initial_capacity);
	}

	if (!sb->buffer) {
		if (!arena) {
			free(sb);
		}
		return NULL;
	}

	sb->length = 0;
	sb->capacity = initial_capacity;
	sb->buffer[0] = '\0';
	return sb;
}

void sb_destroy(StringBuilder *sb) {
	if (sb && !sb->arena) {
		free(sb->buffer);
		free(sb);
	}
}

void sb_append(StringBuilder *sb, const char *str) {
	if (!sb || !str) {
		return;
	}

	size_t str_len = strlen(str);
	sb_ensure_capacity(sb, str_len);

	memcpy(sb->buffer + sb->length, str, str_len + 1);
	sb->length += str_len;
}
void sb_append_char(StringBuilder *sb, char c) {
	if (!sb) {
		return;
	}

	sb_ensure_capacity(sb, 1);
	sb->buffer[sb->length++] = c;
	sb->buffer[sb->length] = '\0';
}

void sb_clear(StringBuilder *sb) {
	if (!sb) {
		return;
	}

	sb->length = 0;
	sb->buffer[0] = '\0';
}

char *sb_to_string(StringBuilder *sb) {
	if (!sb) {
		return NULL;
	}

	char *result;
	if (sb->arena) {
		result = arena_alloc(sb->arena, sb->length + 1);
	} else {
		result = malloc(sb->length + 1);
	}

	if (!result) {
		return NULL;
	}

	memcpy(result, sb->buffer, sb->length + 1);
	return result;
}

size_t sb_length(StringBuilder *sb) {
	if (!sb) {
		return 0;
	}
	return sb->length;
}

size_t sb_capacity(StringBuilder *sb) {
	if (!sb) {
		return 0;
	}
	return sb->capacity;
}

bool sb_is_empty(StringBuilder *sb) {
	if (!sb) {
		return true;
	}
	return sb->length == 0;
}

void sb_ensure_capacity(StringBuilder *sb, size_t additional_length) {
	if (!sb) {
		return;
	}

	size_t required_capacity = sb->length + additional_length + 1;
	if (required_capacity > sb->capacity) {
		size_t new_capacity = sb->capacity;
		while (new_capacity < required_capacity) {
			new_capacity *= 2;
		}

		if (sb->arena) {
			char *new_buffer = arena_alloc(sb->arena, new_capacity);
			if (!new_buffer) {
				return;
			}
			memcpy(new_buffer, sb->buffer, sb->length + 1);
			sb->buffer = new_buffer;
		} else {
			char *new_buffer = realloc(sb->buffer, new_capacity);
			if (!new_buffer) {
				return;
			}
			sb->buffer = new_buffer;
		}
		sb->capacity = new_capacity;
	}
}