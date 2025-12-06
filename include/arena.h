#pragma once

#include <stddef.h>

#define ARENA_BLOCK_SIZE (1024 * 64) // 64KB

typedef struct ArenaBlock {
	struct ArenaBlock *next;
	size_t size;
	size_t offset;
	char data[];
} ArenaBlock;

typedef struct Arena {
	ArenaBlock *head;
} Arena;

Arena *arena_create();
void *arena_alloc(Arena *arena, size_t size);
void arena_destroy(Arena *arena);
char *arena_str_duplicate(Arena *arena, const char *str);
