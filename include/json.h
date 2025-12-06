#pragma once

#include "map.h"
#include <stddef.h>

struct Arena;

enum JSONValueType {
	JSON_NULL,
	JSON_BOOL,
	JSON_NUMBER,
	JSON_STRING,
	JSON_ARRAY,
	JSON_OBJECT
};

struct JsonValue {
	enum JSONValueType type;
	union {
		int bool_value;
		double number_value;
		char *string_value;
		struct {
			struct JsonValue **items;
			size_t count;
			size_t capacity; // For arena allocation
		} array_value;
		struct Map *object_value;
	};
	struct Arena *arena;
};

struct JsonValue *json_parse(struct Arena *arena, char *json_str);
char *json_serialize(struct Arena *arena, const struct JsonValue *value);

void json_free(struct JsonValue *value);

struct JsonValue *json_get_object_value(const struct JsonValue *object,
										const char *key);

struct JsonValue *json_get_array_element(const struct JsonValue *array,
										 size_t index);
size_t json_get_array_size(const struct JsonValue *array);
int json_get_bool(const struct JsonValue *value);
double json_get_number(const struct JsonValue *value);
const char *json_get_string(const struct JsonValue *value);

bool json_is_null(const struct JsonValue *value);
bool json_is_bool(const struct JsonValue *value);
bool json_is_number(const struct JsonValue *value);
bool json_is_string(const struct JsonValue *value);
bool json_is_array(const struct JsonValue *value);
bool json_is_object(const struct JsonValue *value);

struct JsonValue *json_create_null(struct Arena *arena);
struct JsonValue *json_create_bool(struct Arena *arena, int bool_value);
struct JsonValue *json_create_number(struct Arena *arena, double number_value);
struct JsonValue *json_create_string(struct Arena *arena,
									 const char *string_value);
struct JsonValue *json_create_array(struct Arena *arena);
struct JsonValue *json_create_object(struct Arena *arena);
