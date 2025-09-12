#pragma once

#include <map.h>
#include <stddef.h>

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
		} array_value;
		struct Map *object_value;
	};
};

struct JsonValue *json_parse(const char *json_str);
char *json_serialize(const struct JsonValue *value);

void json_free(struct JsonValue *value);

struct JsonValue *json_get_object_value(const struct JsonValue *object,
										const char *key);

struct JsonValue *json_get_array_element(const struct JsonValue *array,
										 size_t index);
size_t json_get_array_size(const struct JsonValue *array);
int json_get_bool(const struct JsonValue *value);
double json_get_number(const struct JsonValue *value);
const char *json_get_string(const struct JsonValue *value);

int json_is_null(const struct JsonValue *value);
int json_is_bool(const struct JsonValue *value);
int json_is_number(const struct JsonValue *value);
int json_is_string(const struct JsonValue *value);
int json_is_array(const struct JsonValue *value);
int json_is_object(const struct JsonValue *value);

struct JsonValue *json_create_null(); // Creates a JSON null value (Should just
									  // be static const honestly)
struct JsonValue *json_create_bool(int bool_value);
struct JsonValue *json_create_number(double number_value);

/*
 * Creates a JSON string value
 * @param const char* - The string value (will be duplicated)
 * @return struct JsonValue* - A pointer to the newly created JSON string value
 */
struct JsonValue *json_create_string(const char *string_value);

struct JsonValue *json_create_array();
struct JsonValue *json_create_object();
