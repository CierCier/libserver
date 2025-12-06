#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>

struct Arena;

struct MapEntry {
	char *key;
	void *value;
	struct MapEntry *next;
};

struct Map {
	struct MapEntry **buckets;
	size_t bucket_count;
	pthread_mutex_t lock;
	struct Arena *arena;
};

void map_init(struct Map *map, struct Arena *arena, size_t bucket_count);
void map_destroy(struct Map *map);

void *map_put(struct Map *map, const char *key, void *value);
void *map_get(struct Map *map, const char *key);
bool map_remove(struct Map *map, const char *key);
bool map_contains(struct Map *map, const char *key);

size_t map_size(struct Map *map);
void map_clear(struct Map *map);

size_t hash_string(const char *str);

size_t next_prime(size_t n);
bool is_prime(size_t n);
size_t prev_prime(size_t n);
