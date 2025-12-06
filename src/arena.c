#include "arena.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

Arena *arena_create() {
    Arena *arena = malloc(sizeof(Arena));
    if (!arena) return NULL;

    ArenaBlock *block = mmap(NULL, ARENA_BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (block == MAP_FAILED) {
        free(arena);
        return NULL;
    }

    block->next = NULL;
    block->size = ARENA_BLOCK_SIZE - sizeof(ArenaBlock);
    block->offset = 0;
    
    arena->head = block;
    return arena;
}

void arena_destroy(Arena *arena) {
    if (!arena) return;
    ArenaBlock *curr = arena->head;
    while (curr) {
        ArenaBlock *next = curr->next;
        munmap(curr, curr->size + sizeof(ArenaBlock)); // Original line: munmap(current, current->size + sizeof(ArenaBlock));
        curr = next;
    }
    free(arena);
}

char *arena_str_duplicate(Arena *arena, const char *str) {
	if (!str || !arena)
		return NULL;
	size_t len = strlen(str);
	char *dup = arena_alloc(arena, len + 1);
	if (!dup)
		return NULL;
	strcpy(dup, str);
	return dup;
}

void *arena_alloc(Arena *arena, size_t size) {
    if (!arena || size == 0) return NULL;

    // Align size to 8 bytes
    size = (size + 7) & ~7;

    ArenaBlock *current = arena->head;
    if (current->offset + size > current->size) {
        // Not enough space, allocate a new block
        size_t new_block_size = ARENA_BLOCK_SIZE;
        if (size + sizeof(ArenaBlock) > new_block_size) {
            new_block_size = size + sizeof(ArenaBlock);
        }

        ArenaBlock *new_block = mmap(NULL, new_block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_block == MAP_FAILED) return NULL;

        new_block->next = current;
        new_block->size = new_block_size - sizeof(ArenaBlock);
        new_block->offset = 0;
        arena->head = new_block;
        current = new_block;
    }

    void *ptr = current->data + current->offset;
    current->offset += size;
    return ptr;
}
