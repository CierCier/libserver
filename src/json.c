#include "json.h"
#include "arena.h"
#include "map.h"
#include "stringbuilder.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declarations
static void skip_ws(const char **p);
static struct JsonValue *parse_value(struct Arena *arena, char **p);
static struct JsonValue *parse_object(struct Arena *arena, char **p);
static struct JsonValue *parse_array(struct Arena *arena, char **p);
static struct JsonValue *parse_string(struct Arena *arena, char **p);
static struct JsonValue *parse_number(struct Arena *arena, char **p);
static int match(char **p, const char *kw);
static int expect_char(char **p, char c);
static char hex_to_char(const char *h4, int *ok);
static void append_escaped_string(StringBuilder *sb, const char *s);
static struct JsonValue *make_value(struct Arena *arena, enum JSONValueType t);

static struct JsonValue g_null_instance = {.type = JSON_NULL, .arena = NULL};

struct JsonValue *json_parse(struct Arena *arena, char *json_str) {
	if (!json_str)
		return NULL;
	char *p = json_str;
	skip_ws((const char **)&p);
	struct JsonValue *v = parse_value(arena, &p);
	if (!v)
		return NULL;
	skip_ws((const char **)&p);
	if (*p != '\0') {
		return NULL; // Trailing characters
	}
	return v;
}

char *json_serialize(struct Arena *arena, const struct JsonValue *value) {
	StringBuilder *sb = sb_create(arena, 256);
	if (!sb)
		return NULL;

	if (!value) {
		sb_append(sb, "null");
		return sb_to_string(sb);
	}

	switch (value->type) {
	case JSON_NULL:
		sb_append(sb, "null");
		break;
	case JSON_BOOL:
		sb_append(sb, value->bool_value ? "true" : "false");
		break;
	case JSON_NUMBER: {
		char buffer[64];
		snprintf(buffer, sizeof(buffer), "%g", value->number_value);
		sb_append(sb, buffer);
		break;
	}
	case JSON_STRING:
		sb_append_char(sb, '"');
		append_escaped_string(sb, value->string_value);
		sb_append_char(sb, '"');
		break;
	case JSON_ARRAY:
		sb_append_char(sb, '[');
		for (size_t i = 0; i < value->array_value.count; i++) {
			if (i > 0)
				sb_append_char(sb, ',');
			char *elem_str = json_serialize(arena, value->array_value.items[i]);
			if (elem_str) {
				sb_append(sb, elem_str);
			}
		}
		sb_append_char(sb, ']');
		break;
	case JSON_OBJECT: {
		sb_append_char(sb, '{');
		if (value->object_value) {
			size_t emitted = 0;
			for (size_t i = 0; i < value->object_value->bucket_count; i++) {
				struct MapEntry *entry = value->object_value->buckets[i];
				while (entry) {
					if (emitted++ > 0)
						sb_append_char(sb, ',');
					sb_append_char(sb, '"');
					append_escaped_string(sb, entry->key);
					sb_append(sb, ":");
					char *val_str = json_serialize(
						arena, (const struct JsonValue *)entry->value);
					if (val_str) {
						sb_append(sb, val_str);
					} else {
						sb_append(sb, "null");
					}
					entry = entry->next;
				}
			}
		}
		sb_append_char(sb, '}');
		break;
	}
	}
	return sb_to_string(sb);
}

void json_free(struct JsonValue *value) {
	if (!value || value->arena != NULL || value == &g_null_instance) {
		return;
	}

	switch (value->type) {
	case JSON_STRING:
		free(value->string_value);
		break;
	case JSON_ARRAY:
		if (value->array_value.items) {
			for (size_t i = 0; i < value->array_value.count; i++) {
				json_free(value->array_value.items[i]);
			}
			free(value->array_value.items);
		}
		break;
	case JSON_OBJECT:
		if (value->object_value) {
			// This assumes map keys are arena allocated or literals, but values
			// are json_values
			for (size_t i = 0; i < value->object_value->bucket_count; i++) {
				struct MapEntry *entry = value->object_value->buckets[i];
				while (entry) {
					json_free((struct JsonValue *)entry->value);
					entry = entry->next;
				}
			}
			map_destroy(value->object_value);
			free(value->object_value);
		}
		break;
	default:
		break;
	}
	free(value);
}

struct JsonValue *json_get_object_value(const struct JsonValue *object,
										const char *key) {
	if (!object || object->type != JSON_OBJECT || !key)
		return NULL;
	return (struct JsonValue *)map_get(object->object_value, key);
}
bool json_is_null(const struct JsonValue *v) {
	return v && v->type == JSON_NULL;
}
bool json_is_bool(const struct JsonValue *v) {
	return v && v->type == JSON_BOOL;
}
bool json_is_number(const struct JsonValue *v) {
	return v && v->type == JSON_NUMBER;
}
bool json_is_string(const struct JsonValue *v) {
	return v && v->type == JSON_STRING;
}
bool json_is_array(const struct JsonValue *v) {
	return v && v->type == JSON_ARRAY;
}
bool json_is_object(const struct JsonValue *v) {
	return v && v->type == JSON_OBJECT;
}

size_t json_get_array_size(const struct JsonValue *array) {
	if (!array || array->type != JSON_ARRAY)
		return 0;
	return array->array_value.count;
}

struct JsonValue *json_get_array_element(const struct JsonValue *array,
										 size_t index) {
	if (!array || array->type != JSON_ARRAY ||
		index >= array->array_value.count)
		return NULL;
	return array->array_value.items[index];
}

struct JsonValue *json_create_object(struct Arena *arena) {
	struct JsonValue *v = make_value(arena, JSON_OBJECT);
	if (!v)
		return NULL;
	v->object_value = arena_alloc(arena, sizeof(struct Map));
	if (v->object_value)
		map_init(v->object_value, arena, 17);
	return v;
}

struct JsonValue *json_create_string(struct Arena *arena, const char *str) {
	struct JsonValue *v = make_value(arena, JSON_STRING);
	if (!v)
		return NULL;
	v->string_value = arena_str_duplicate(arena, str);
	return v;
}

struct JsonValue *json_create_null(struct Arena *arena) {
	(void)arena; // Null values use a static instance
	return &g_null_instance;
}

struct JsonValue *json_create_bool(struct Arena *arena, int bool_value) {
	struct JsonValue *v = make_value(arena, JSON_BOOL);
	if (!v)
		return NULL;
	v->bool_value = bool_value ? true : false;
	return v;
}

struct JsonValue *json_create_number(struct Arena *arena, double number_value) {
	struct JsonValue *v = make_value(arena, JSON_NUMBER);
	if (!v)
		return NULL;
	v->number_value = number_value;
	return v;
}

struct JsonValue *json_create_array(struct Arena *arena) {
	struct JsonValue *v = make_value(arena, JSON_ARRAY);
	if (!v)
		return NULL;
	v->array_value.items = NULL;
	v->array_value.count = 0;
	v->array_value.capacity = 0;
	return v;
}

// Implementations

static void skip_ws(const char **p) {
	while (**p && isspace(**p))
		(*p)++;
}

static struct JsonValue *make_value(struct Arena *arena, enum JSONValueType t) {
	struct JsonValue *v = arena_alloc(arena, sizeof(struct JsonValue));
	if (!v)
		return NULL;
	v->type = t;
	v->arena = arena;
	return v;
}

static int match(char **p, const char *kw) {
	size_t len = strlen(kw);
	if (strncmp(*p, kw, len) == 0) {
		*p += len;
		return 1;
	}
	return 0;
}

static int expect_char(char **p, char c) {
	if (**p == c) {
		(*p)++;
		return 1;
	}
	return 0;
}

static struct JsonValue *parse_value(struct Arena *arena, char **p) {
	skip_ws((const char **)p);
	char c = **p;
	if (!c)
		return NULL;
	if (c == '{')
		return parse_object(arena, p);
	if (c == '[')
		return parse_array(arena, p);
	if (c == '"')
		return parse_string(arena, p);
	if (c == '-' || isdigit(c))
		return parse_number(arena, p);
	if (match(p, "true")) {
		struct JsonValue *v = make_value(arena, JSON_BOOL);
		if (v)
			v->bool_value = true;
		return v;
	}
	if (match(p, "false")) {
		struct JsonValue *v = make_value(arena, JSON_BOOL);
		if (v)
			v->bool_value = false;
		return v;
	}
	if (match(p, "null"))
		return &g_null_instance;
	return NULL;
}

static struct JsonValue *parse_object(struct Arena *arena, char **p) {
	if (!expect_char(p, '{'))
		return NULL;
	struct JsonValue *v = make_value(arena, JSON_OBJECT);
	if (!v)
		return NULL;
	v->object_value = arena_alloc(arena, sizeof(struct Map));
	if (!v->object_value)
		return NULL;
	map_init(v->object_value, arena, 17);

	skip_ws((const char **)p);
	if (**p == '}') {
		(*p)++;
		return v;
	}

	while (1) {
		skip_ws((const char **)p);
		struct JsonValue *key = parse_string(arena, p);
		if (!key)
			return NULL;

		skip_ws((const char **)p);
		if (!expect_char(p, ':'))
			return NULL;

		struct JsonValue *val = parse_value(arena, p);
		if (!val)
			return NULL;

		map_put(v->object_value, key->string_value, val);

		skip_ws((const char **)p);
		if (**p == ',') {
			(*p)++;
		} else if (**p == '}') {
			(*p)++;
			break;
		} else {
			return NULL;
		}
	}
	return v;
}

static struct JsonValue *parse_array(struct Arena *arena, char **p) {
	if (!expect_char(p, '['))
		return NULL;
	struct JsonValue *v = make_value(arena, JSON_ARRAY);
	if (!v)
		return NULL;

	// Temporary storage for items
	size_t cap = 8;
	size_t count = 0;
	struct JsonValue **items =
		arena_alloc(arena, cap * sizeof(struct JsonValue *));
	if (!items)
		return NULL;

	skip_ws((const char **)p);
	if (**p == ']') {
		(*p)++;
		v->array_value.count = 0;
		v->array_value.items = NULL;
		return v;
	}

	while (1) {
		struct JsonValue *elem = parse_value(arena, p);
		if (!elem)
			return NULL;

		if (count == cap) {
			// Simple arena realloc/grow
			size_t new_cap = cap * 2;
			struct JsonValue **new_items =
				arena_alloc(arena, new_cap * sizeof(struct JsonValue *));
			if (!new_items)
				return NULL;
			memcpy(new_items, items, count * sizeof(struct JsonValue *));
			items = new_items;
			cap = new_cap;
		}
		items[count++] = elem;

		skip_ws((const char **)p);
		if (**p == ',') {
			(*p)++;
		} else if (**p == ']') {
			(*p)++;
			break;
		} else {
			return NULL;
		}
	}
	v->array_value.count = count;
	v->array_value.items = items;
	return v;
}

static struct JsonValue *parse_string(struct Arena *arena, char **p) {
	if (!expect_char(p, '"'))
		return NULL;
	char *start = *p;
	char *out = start;

	while (**p) {
		char c = **p;
		if (c == '"') {
			(*p)++;
			*out = '\0';
			struct JsonValue *v = make_value(arena, JSON_STRING);
			if (!v)
				return NULL;
			v->string_value = start;
			return v;
		}
		if (c == '\\') {
			(*p)++;
			if (!**p)
				return NULL;
			char esc = **p;
			(*p)++;
			switch (esc) {
			case '"':
				*out++ = '"';
				break;
			case '\\':
				*out++ = '\\';
				break;
			case '/':
				*out++ = '/';
				break;
			case 'b':
				*out++ = '\b';
				break;
			case 'f':
				*out++ = '\f';
				break;
			case 'n':
				*out++ = '\n';
				break;
			case 'r':
				*out++ = '\r';
				break;
			case 't':
				*out++ = '\t';
				break;
			case 'u': {
				char h4[5];
				if (strlen(*p) < 4)
					return NULL; // Should check bounds safely
				memcpy(h4, *p, 4);
				h4[4] = 0;
				int ok;
				char ch = hex_to_char(h4, &ok);
				if (!ok)
					return NULL;
				*out++ = ch;
				*p += 4;
				break;
			}
			default:
				return NULL;
			}
		} else {
			*out++ = **p;
			(*p)++;
		}
	}
	return NULL;
}

static struct JsonValue *parse_number(struct Arena *arena, char **p) {
	char *start = *p;
	// Validate number format roughly
	if (**p == '-')
		(*p)++;
	if (!isdigit(**p))
		return NULL;
	while (isdigit(**p))
		(*p)++;
	if (**p == '.') {
		(*p)++;
		while (isdigit(**p))
			(*p)++;
	}
	if (**p == 'e' || **p == 'E') {
		(*p)++;
		if (**p == '+' || **p == '-')
			(*p)++;
		while (isdigit(**p))
			(*p)++;
	}

	char *end;
	double d = strtod(start, &end);
	if (end != *p) {
		*p = end;
	}

	struct JsonValue *v = make_value(arena, JSON_NUMBER);
	if (!v)
		return NULL;
	v->number_value = d;
	return v;
}

static char hex_to_char(const char *h4, int *ok) {
	char *end;
	long v = strtol(h4, &end, 16);
	if (end != h4 + 4) {
		*ok = 0;
		return 0;
	}
	*ok = 1;
	return (char)v;
}

static void append_escaped_string(StringBuilder *sb, const char *s) {
	if (!s)
		return;
	while (*s) {
		char c = *s++;
		switch (c) {
		case '"':
			sb_append(sb, "\\\"");
			break;
		case '\\':
			sb_append(sb, "\\\\");
			break;
		case '\b':
			sb_append(sb, "\\b");
			break;
		case '\f':
			sb_append(sb, "\\f");
			break;
		case '\n':
			sb_append(sb, "\\n");
			break;
		case '\r':
			sb_append(sb, "\\r");
			break;
		case '\t':
			sb_append(sb, "\\t");
			break;
		default:
			if (iscntrl(c)) {
				char buf[7];
				sprintf(buf, "\\u%04x", (unsigned char)c);
				sb_append(sb, buf);
			} else {
				sb_append_char(sb, c);
			}
		}
	}
}