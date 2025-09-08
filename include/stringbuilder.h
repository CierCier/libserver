#pragma once

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

// Initial capacity for the string builder (128 bytes)
#define STRINGBUILDER_INITIAL_CAPACITY 128
#define STRINGBUILDER_MAX_CAPACITY MB(128)

struct StringBuilder {
	char *buffer;	 // Pointer to the character buffer
	size_t length;	 // Current length of the string
	size_t capacity; // Current capacity of the buffer
};

struct StringBuilder *sb_create(size_t initial_capacity);

void sb_destroy(struct StringBuilder *sb);

void sb_append(struct StringBuilder *sb, const char *str);
void sb_append_char(struct StringBuilder *sb, char c);

/*
 * Clears the contents of the string builder, resetting its length to 0.
 */
void sb_clear(struct StringBuilder *sb);

/*
 * Consumes the contents of the string builder, returning a pointer to a
 * newly allocated string containing the current contents of the builder.
 * The builder is cleared after this operation.
 */
char *sb_consume(struct StringBuilder *sb);

/*
 * Returns a malloc'ed string containing the current contents of the builder.
 * The builder is not cleared after this operation.
 */
char *sb_to_string(struct StringBuilder *sb);

size_t sb_length(struct StringBuilder *sb);
size_t sb_capacity(struct StringBuilder *sb);

bool sb_is_empty(struct StringBuilder *sb);

/*
 * Ensures that the string builder has enough capacity to append
 * additional_length characters. If not, it resizes the buffer.
 */
void sb_ensure_capacity(struct StringBuilder *sb, size_t additional_length);
