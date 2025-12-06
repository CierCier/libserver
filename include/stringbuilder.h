#pragma once

#include <stdbool.h>
#include <stddef.h>

struct Arena;

#define STRINGBUILDER_INITIAL_CAPACITY 128

typedef struct StringBuilder {
	char *buffer;
	size_t length;
	size_t capacity;
	struct Arena *arena; // If not NULL, use arena for allocations
} StringBuilder;

StringBuilder *sb_create(struct Arena *arena, size_t initial_capacity);
void sb_destroy(StringBuilder *sb);

void sb_append(StringBuilder *sb, const char *str);
void sb_append_char(StringBuilder *sb, char c);

void sb_clear(StringBuilder *sb);

char *sb_to_string(StringBuilder *sb);

size_t sb_length(StringBuilder *sb);
size_t sb_capacity(StringBuilder *sb);
bool sb_is_empty(StringBuilder *sb);

void sb_ensure_capacity(StringBuilder *sb, size_t additional_length);
