#include "map.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>

void map_init(struct Map *map, size_t bucket_count) {
	if (!map)
		return;
	map->bucket_count = next_prime(bucket_count);
	map->buckets = calloc(map->bucket_count, sizeof(struct MapEntry *));
	pthread_mutex_init(&map->lock, NULL);
}

void map_destroy(struct Map *map) {
	if (!map)
		return;
	map_clear(map);
	free(map->buckets);
	pthread_mutex_destroy(&map->lock);
}

bool map_put(struct Map *map, const char *key, void *value) {
	if (!map || !key)
		return false;

	size_t index = hash_string(key) % map->bucket_count;

	pthread_mutex_lock(&map->lock);

	struct MapEntry *entry = map->buckets[index];
	while (entry) {
		if (strcmp(entry->key, key) == 0) {
			entry->value = value; // Update existing value
			pthread_mutex_unlock(&map->lock);
			return true;
		}
		entry = entry->next;
	}

	// Key not found, create a new entry
	struct MapEntry *new_entry = malloc(sizeof(struct MapEntry));
	if (!new_entry) {
		pthread_mutex_unlock(&map->lock);
		return false;
	}

	new_entry->key = str_duplicate(key);
	new_entry->value = value;
	new_entry->next = map->buckets[index];
	map->buckets[index] = new_entry;

	pthread_mutex_unlock(&map->lock);
	return true;
}

void *map_get(struct Map *map, const char *key) {
	if (!map || !key)
		return NULL;

	size_t index = hash_string(key) % map->bucket_count;

	pthread_mutex_lock(&map->lock);

	struct MapEntry *entry = map->buckets[index];
	while (entry) {
		if (strcmp(entry->key, key) == 0) {
			pthread_mutex_unlock(&map->lock);
			return entry->value;
		}
		entry = entry->next;
	}

	pthread_mutex_unlock(&map->lock);
	return NULL; // Key not found
}

bool map_remove(struct Map *map, const char *key) {
	if (!map || !key)
		return false;

	size_t index = hash_string(key) % map->bucket_count;

	pthread_mutex_lock(&map->lock);

	struct MapEntry *entry = map->buckets[index];
	struct MapEntry *prev = NULL;
	while (entry) {
		if (strcmp(entry->key, key) == 0) {
			if (prev) {
				prev->next = entry->next;
			} else {
				map->buckets[index] = entry->next;
			}
			free(entry->key);
			free(entry);
			pthread_mutex_unlock(&map->lock);
			return true;
		}
		prev = entry;
		entry = entry->next;
	}

	pthread_mutex_unlock(&map->lock);
	return false; // Key not found
}

bool map_contains(struct Map *map, const char *key) {
	if (!map || !key)
		return false;

	size_t index = hash_string(key) % map->bucket_count;

	pthread_mutex_lock(&map->lock);

	struct MapEntry *entry = map->buckets[index];
	while (entry) {
		if (strcmp(entry->key, key) == 0) {
			pthread_mutex_unlock(&map->lock);
			return true;
		}
		entry = entry->next;
	}

	pthread_mutex_unlock(&map->lock);
	return false; // Key not found
}

size_t map_size(struct Map *map) {
	if (!map)
		return 0;

	size_t size = 0;
	pthread_mutex_lock(&map->lock);
	for (size_t i = 0; i < map->bucket_count; i++) {
		struct MapEntry *entry = map->buckets[i];
		while (entry) {
			size++;
			entry = entry->next;
		}
	}
	pthread_mutex_unlock(&map->lock);
	return size;
}

void map_clear(struct Map *map) {
	if (!map)
		return;

	pthread_mutex_lock(&map->lock);
	for (size_t i = 0; i < map->bucket_count; i++) {
		struct MapEntry *entry = map->buckets[i];
		while (entry) {
			struct MapEntry *next = entry->next;
			free(entry->key);
			free(entry);
			entry = next;
		}
		map->buckets[i] = NULL;
	}
	pthread_mutex_unlock(&map->lock);
}

size_t hash_string(const char *str) {
	// djb2 hash function
	// Source: http://www.cse.yorku.ca/~oz/hash.html
	size_t hash = 5381;
	int c;
	while ((c = *str++)) {
		hash = hash * 33 ^ c;
	}
	return hash;
}

size_t next_prime(size_t n) {
	if (n <= 2)
		return 2;
	if (n % 2 == 0)
		n++;
	while (!is_prime(n)) {
		n += 2;
	}
	return n;
}
bool is_prime(size_t n) {
	if (n <= 1)
		return false;
	if (n <= 3)
		return true;
	if (n % 2 == 0 || n % 3 == 0)
		return false;
	for (size_t i = 5; i * i <= n; i += 6) {
		if (n % i == 0 || n % (i + 2) == 0)
			return false;
	}
	return true;
}
size_t prev_prime(size_t n) {
	if (n <= 2)
		return 0; // No prime less than 2
	if (n % 2 == 0)
		n--;
	else
		n -= 2;
	while (n >= 2 && !is_prime(n)) {
		n -= 2;
	}
	return n;
}
