#include "json.h"
#include "map.h"
#include "stringbuilder.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declarations
static void skip_ws(const char **p);
static struct JsonValue *parse_value(const char **p);
static struct JsonValue *parse_object(const char **p);
static struct JsonValue *parse_array(const char **p);
static struct JsonValue *parse_string(const char **p);
static struct JsonValue *parse_number(const char **p);
static int match(const char **p, const char *kw);
static int expect_char(const char **p, char c);
static char hex_to_char(const char *h4, int *ok);
static void append_escaped_string(struct StringBuilder *sb, const char *s);

struct JsonValue *json_parse(const char *json_str) {
	if (!json_str)
		return NULL;
	const char *p = json_str;
	skip_ws(&p);
	struct JsonValue *v = parse_value(&p);
	if (!v)
		return NULL;
	skip_ws(&p);
	// If trailing characters exist and are non-whitespace, treat as error
	if (*p != '\0') {
		json_free(v);
		return NULL;
	}
	return v;
}

char *json_serialize(const struct JsonValue *value) {
	struct StringBuilder *sb = sb_create(4);
	if (!sb)
		return NULL;

	if (!value) {
		sb_append(sb, "null");
		char *result = sb_consume(sb);
		sb_destroy(sb);
		return result;
	}
	switch (value->type) {
	case JSON_NULL:
		sb_append(sb, "null");
		break;
	case JSON_BOOL:
		if (value->bool_value)
			sb_append(sb, "true");
		else
			sb_append(sb, "false");
		break;
	case JSON_NUMBER: {
		char buffer[32];
		snprintf(buffer, sizeof(buffer), "%lf", value->number_value);
		sb_append(sb, buffer);
		break;
	}
	case JSON_STRING:
		sb_append(sb, "\"");
		for (const char *p = value->string_value; *p; p++) {
			switch (*p) {
			case '\"':
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
				if ((unsigned char)*p < 0x20) {
					char buffer[7];
					snprintf(buffer, sizeof(buffer), "\\u%04x",
							 (unsigned char)*p);
					sb_append(sb, buffer);
				} else {
					sb_append_char(sb, *p);
				}
				break;
			}
		}
		sb_append(sb, "\"");
		break;
	case JSON_ARRAY:
		sb_append(sb, "[");
		for (size_t i = 0; i < value->array_value.count; i++) {
			if (i > 0)
				sb_append(sb, ",");
			char *elem_str = json_serialize(value->array_value.items[i]);
			if (!elem_str) {
				sb_destroy(sb);
				return NULL;
			}
			sb_append(sb, elem_str);
			free(elem_str);
		}
		sb_append(sb, "]");
		break;
	case JSON_OBJECT: {
		sb_append(sb, "{");
		if (value->object_value) {
			size_t emitted = 0;
			struct Map *map = value->object_value;
			for (size_t i = 0; i < map->bucket_count; i++) {
				struct MapEntry *entry = map->buckets[i];
				while (entry) {
					if (emitted++ > 0)
						sb_append(sb, ",");
					// Serialize key
					sb_append(sb, "\"");
					append_escaped_string(sb, entry->key);
					sb_append(sb, "\":");
					// Serialize value
					char *val_str =
						json_serialize((const struct JsonValue *)entry->value);
					if (!val_str) {
						// On failure, insert null
						sb_append(sb, "null");
					} else {
						sb_append(sb, val_str);
						free(val_str);
					}
					entry = entry->next;
				}
			}
		}
		sb_append(sb, "}");
		break;
	}
	}

	char *result = sb_consume(sb);
	sb_destroy(sb);
	return result;
}

void json_free(struct JsonValue *value) {
	if (!value)
		return;
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
			struct Map *map = value->object_value;
			for (size_t i = 0; i < map->bucket_count; i++) {
				struct MapEntry *entry = map->buckets[i];
				while (entry) {
					json_free((struct JsonValue *)entry->value);
					entry = entry->next;
				}
			}
			map_destroy(value->object_value);
			free(value->object_value);
		}
		break;
	case JSON_NULL:
	case JSON_BOOL:
	case JSON_NUMBER:
	default:
		break;
	}
	free(value);
}

struct JsonValue *json_get_object_value(const struct JsonValue *object,
										const char *key) {
	if (!object || object->type != JSON_OBJECT || !key || !object->object_value)
		return NULL;
	return (struct JsonValue *)map_get(object->object_value, key);
}

struct JsonValue *json_get_array_element(const struct JsonValue *array,
										 size_t index) {
	if (!array || array->type != JSON_ARRAY)
		return NULL;
	if (index >= array->array_value.count)
		return NULL;
	return array->array_value.items[index];
}

size_t json_get_array_size(const struct JsonValue *array) {
	if (!array || array->type != JSON_ARRAY)
		return 0;
	return array->array_value.count;
}

int json_get_bool(const struct JsonValue *value) {
	if (!value || value->type != JSON_BOOL)
		return 0;
	return value->bool_value ? 1 : 0;
}

double json_get_number(const struct JsonValue *value) {
	if (!value || value->type != JSON_NUMBER)
		return 0.0;
	return value->number_value;
}

const char *json_get_string(const struct JsonValue *value) {
	if (!value || value->type != JSON_STRING)
		return NULL;
	return value->string_value;
}

int json_is_null(const struct JsonValue *value) {
	return value && value->type == JSON_NULL;
}
int json_is_bool(const struct JsonValue *value) {
	return value && value->type == JSON_BOOL;
}
int json_is_number(const struct JsonValue *value) {
	return value && value->type == JSON_NUMBER;
}
int json_is_string(const struct JsonValue *value) {
	return value && value->type == JSON_STRING;
}
int json_is_array(const struct JsonValue *value) {
	return value && value->type == JSON_ARRAY;
}
int json_is_object(const struct JsonValue *value) {
	return value && value->type == JSON_OBJECT;
}

// ---------------- Parsing helpers ----------------
static void skip_ws(const char **p) {
	while (**p && isspace((unsigned char)**p))
		(*p)++;
}

static int match(const char **p, const char *kw) {
	size_t n = strlen(kw);
	if (strncmp(*p, kw, n) == 0) {
		*p += n;
		return 1;
	}
	return 0;
}

static int expect_char(const char **p, char c) {
	skip_ws(p);
	if (**p == c) {
		(*p)++;
		return 1;
	}
	return 0;
}

static struct JsonValue *make_value(enum JSONValueType t) {
	struct JsonValue *v = (struct JsonValue *)malloc(sizeof(struct JsonValue));
	if (!v)
		return NULL;
	memset(v, 0, sizeof(*v));
	v->type = t;
	return v;
}

static struct JsonValue *parse_value(const char **p) {
	skip_ws(p);
	char c = **p;
	if (c == '"')
		return parse_string(p);
	if (c == '{')
		return parse_object(p);
	if (c == '[')
		return parse_array(p);
	if (c == '-' || (c >= '0' && c <= '9'))
		return parse_number(p);
	if (match(p, "true")) {
		struct JsonValue *v = make_value(JSON_BOOL);
		if (v)
			v->bool_value = 1;
		return v;
	}
	if (match(p, "false")) {
		struct JsonValue *v = make_value(JSON_BOOL);
		if (v)
			v->bool_value = 0;
		return v;
	}
	if (match(p, "null")) {
		return make_value(JSON_NULL);
	}
	return NULL;
}

static char hex_to_char(const char *h4, int *ok) {
	int v = 0;
	*ok = 1;
	for (int i = 0; i < 4; i++) {
		char ch = h4[i];
		int d;
		if (ch >= '0' && ch <= '9')
			d = ch - '0';
		else if (ch >= 'a' && ch <= 'f')
			d = ch - 'a' + 10;
		else if (ch >= 'A' && ch <= 'F')
			d = ch - 'A' + 10;
		else {
			*ok = 0;
			return '\0';
		}
		v = (v << 4) | d;
	}
	if (v <= 0xFF)
		return (char)v; // simplistic; not full UTF-16 handling
	return '?';
}

static struct JsonValue *parse_string(const char **p) {
	if (!expect_char(p, '"'))
		return NULL;
	const char *s = *p;
	struct StringBuilder *sb = sb_create(32);
	if (!sb)
		return NULL;
	while (**p) {
		char ch = **p;
		if (ch == '"') {
			(*p)++;
			break;
		}
		if (ch == '\\') {
			(*p)++;
			char esc = **p;
			if (!esc) {
				sb_destroy(sb);
				return NULL;
			}
			switch (esc) {
			case '"':
				sb_append_char(sb, '"');
				(*p)++;
				break;
			case '\\':
				sb_append_char(sb, '\\');
				(*p)++;
				break;
			case '/':
				sb_append_char(sb, '/');
				(*p)++;
				break;
			case 'b':
				sb_append_char(sb, '\b');
				(*p)++;
				break;
			case 'f':
				sb_append_char(sb, '\f');
				(*p)++;
				break;
			case 'n':
				sb_append_char(sb, '\n');
				(*p)++;
				break;
			case 'r':
				sb_append_char(sb, '\r');
				(*p)++;
				break;
			case 't':
				sb_append_char(sb, '\t');
				(*p)++;
				break;
			case 'u': {
				if ((*p)[1] && (*p)[2] && (*p)[3] && (*p)[4]) {
					int ok = 0;
					char c8 = hex_to_char((*p) + 1, &ok);
					if (!ok) {
						sb_destroy(sb);
						return NULL;
					}
					sb_append_char(sb, c8);
					(*p) += 5;
				} else {
					sb_destroy(sb);
					return NULL;
				}
				break;
			}
			default:
				sb_destroy(sb);
				return NULL;
			}
		} else {
			sb_append_char(sb, ch);
			(*p)++;
		}
	}
	char *out = sb_consume(sb);
	sb_destroy(sb);
	if (!out)
		return NULL;
	struct JsonValue *v = make_value(JSON_STRING);
	if (!v) {
		free(out);
		return NULL;
	}
	v->string_value = out;
	return v;
}

static struct JsonValue *parse_number(const char **p) {
	const char *start = *p;
	if (**p == '-')
		(*p)++;
	if (**p == '0') {
		(*p)++;
	} else if (isdigit((unsigned char)**p)) {
		while (isdigit((unsigned char)**p))
			(*p)++;
	} else
		return NULL;
	if (**p == '.') {
		(*p)++;
		if (!isdigit((unsigned char)**p))
			return NULL;
		while (isdigit((unsigned char)**p))
			(*p)++;
	}
	if (**p == 'e' || **p == 'E') {
		(*p)++;
		if (**p == '+' || **p == '-')
			(*p)++;
		if (!isdigit((unsigned char)**p))
			return NULL;
		while (isdigit((unsigned char)**p))
			(*p)++;
	}
	double val = strtod(start, NULL);
	struct JsonValue *v = make_value(JSON_NUMBER);
	if (!v)
		return NULL;
	v->number_value = val;
	return v;
}

static struct JsonValue *parse_array(const char **p) {
	if (!expect_char(p, '['))
		return NULL;
	skip_ws(p);
	struct JsonValue *v = make_value(JSON_ARRAY);
	if (!v)
		return NULL;
	v->array_value.items = NULL;
	v->array_value.count = 0;
	if (expect_char(p, ']'))
		return v; // empty array
	while (1) {
		struct JsonValue *elem = parse_value(p);
		if (!elem) {
			json_free(v);
			return NULL;
		}
		struct JsonValue **new_items =
			realloc(v->array_value.items,
					(v->array_value.count + 1) * sizeof(*new_items));
		if (!new_items) {
			json_free(elem);
			json_free(v);
			return NULL;
		}
		v->array_value.items = new_items;
		v->array_value.items[v->array_value.count++] = elem;
		skip_ws(p);
		if (expect_char(p, ']'))
			break;
		if (!expect_char(p, ',')) {
			json_free(v);
			return NULL;
		}
		skip_ws(p);
	}
	return v;
}

static struct JsonValue *parse_object(const char **p) {
	if (!expect_char(p, '{'))
		return NULL;
	skip_ws(p);
	struct JsonValue *v = make_value(JSON_OBJECT);
	if (!v)
		return NULL;
	v->object_value = (struct Map *)malloc(sizeof(struct Map));
	if (!v->object_value) {
		free(v);
		return NULL;
	}
	map_init(v->object_value, 17);
	if (expect_char(p, '}'))
		return v; // empty object
	while (1) {
		// key string
		struct JsonValue *k = parse_string(p);
		if (!k || k->type != JSON_STRING) {
			if (k)
				json_free(k);
			json_free(v);
			return NULL;
		}
		skip_ws(p);
		if (!expect_char(p, ':')) {
			json_free(k);
			json_free(v);
			return NULL;
		}
		skip_ws(p);
		struct JsonValue *val = parse_value(p);
		if (!val) {
			json_free(k);
			json_free(v);
			return NULL;
		}
		// put into map (duplicate key string for map)
		map_put(v->object_value, k->string_value, val);
		json_free(k); // frees key string
		skip_ws(p);
		if (expect_char(p, '}'))
			break;
		if (!expect_char(p, ',')) {
			json_free(v);
			return NULL;
		}
		skip_ws(p);
	}
	return v;
}

static void append_escaped_string(struct StringBuilder *sb, const char *s) {
	for (const char *p = s; *p; p++) {
		switch (*p) {
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
			if ((unsigned char)*p < 0x20) {
				char buffer[7];
				snprintf(buffer, sizeof(buffer), "\\u%04x", (unsigned char)*p);
				sb_append(sb, buffer);
			} else {
				sb_append_char(sb, *p);
			}
		}
	}
}

struct JsonValue *json_create_null() {
	static struct JsonValue null_instance = {.type = JSON_NULL};
	return &null_instance;
}

struct JsonValue *json_create_bool(int bool_value) {
	struct JsonValue *v = make_value(JSON_BOOL);
	if (v)
		v->bool_value = bool_value ? 1 : 0;
	return v;
}

struct JsonValue *json_create_number(double number_value) {
	struct JsonValue *v = make_value(JSON_NUMBER);
	if (v)
		v->number_value = number_value;
	return v;
}

struct JsonValue *json_create_string(const char *string_value) {
	if (!string_value)
		return NULL;
	struct JsonValue *v = make_value(JSON_STRING);
	if (!v)
		return NULL;
	v->string_value = malloc(strlen(string_value) + 1);
	if (!v->string_value) {
		free(v);
		return NULL;
	}
	strcpy(v->string_value, string_value);
	return v;
}

struct JsonValue *json_create_array() {
	struct JsonValue *v = make_value(JSON_ARRAY);
	if (v) {
		v->array_value.items = NULL;
		v->array_value.count = 0;
	}
	return v;
}

struct JsonValue *json_create_object() {
	struct JsonValue *v = make_value(JSON_OBJECT);
	if (v) {
		v->object_value = (struct Map *)malloc(sizeof(struct Map));
		if (!v->object_value) {
			free(v);
			return NULL;
		}
		map_init(v->object_value, 17);
	}
	return v;
}