#include "common.h"
#include "map.h"
#include "stringbuilder.h"
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// This function uses malloc/realloc because it's for server setup, not
// per-request. The allocated memory lives for the duration of the server.
static bool compile_route_pattern(const char *path, regex_t *out_regex,
								  char ***out_param_names,
								  size_t *out_param_count, bool *out_is_pat) {
	bool has_param = strchr(path, ':') != NULL;
	if (out_is_pat)
		*out_is_pat = has_param;
	if (!has_param) {
		if (out_param_names)
			*out_param_names = NULL;
		if (out_param_count)
			*out_param_count = 0;
		return true;
	}

	size_t len = strlen(path);
	size_t cap = len * 4 + 16;
	char *regex_buf = malloc(cap);
	if (!regex_buf)
		return false;
	size_t ri = 0;
	size_t param_cap = 4, param_count = 0;
	char **param_names = malloc(param_cap * sizeof(char *));
	if (!param_names) {
		free(regex_buf);
		return false;
	}

	regex_buf[ri++] = '^';
	for (size_t i = 0; i < len; i++) {
		char c = path[i];
		if (c == ':') {
			size_t start = ++i;
			while (i < len && path[i] != '/' && path[i] != 0)
				i++;
			size_t plen = i - start;
			char *pname = malloc(plen + 1);
			if (!pname) {
				for (size_t k = 0; k < param_count; k++)
					free(param_names[k]);
				free(param_names);
				free(regex_buf);
				return false;
			}
			memcpy(pname, &path[start], plen);
			pname[plen] = '\0';
			if (param_count == param_cap) {
				param_cap *= 2;
				char **tmp = realloc(param_names, param_cap * sizeof(char *));
				if (!tmp) {
					for (size_t k = 0; k < param_count; k++)
						free(param_names[k]);
					free(param_names);
					free(regex_buf);
					free(pname);
					return false;
				}
				param_names = tmp;
			}
			param_names[param_count++] = pname;
			const char *capgrp = "([^/]+)";
			size_t cglen = strlen(capgrp);
			memcpy(&regex_buf[ri], capgrp, cglen);
			ri += cglen;
			i--;
		} else {
			if (strchr(".^$|()[]{}+?\\", c)) {
				regex_buf[ri++] = '\\';
			}
			regex_buf[ri++] = c;
		}
		if (ri + 8 >= cap) {
			cap *= 2;
			char *tmpb = realloc(regex_buf, cap);
			if (!tmpb) {
				for (size_t k = 0; k < param_count; k++)
					free(param_names[k]);
				free(param_names);
				free(regex_buf);
				return false;
			}
			regex_buf = tmpb;
		}
	}
	regex_buf[ri++] = '$';
	regex_buf[ri] = '\0';

	int rc = regcomp(out_regex, regex_buf, REG_EXTENDED);
	free(regex_buf);
	if (rc != 0) {
		for (size_t k = 0; k < param_count; k++)
			free(param_names[k]);
		free(param_names);
		return false;
	}
	if (out_param_names)
		*out_param_names = param_names;
	else {
		for (size_t k = 0; k < param_count; k++)
			free(param_names[k]);
		free(param_names);
	}
	if (out_param_count)
		*out_param_count = param_count;
	return true;
}

struct EndPoint *endpoint_create(HttpMethod method, const char *path,
								 RequestHandler handler) {
	struct EndPoint *endpoint = malloc(sizeof(struct EndPoint));
	if (!endpoint)
		return NULL;

	endpoint->method = method;
	endpoint->path = str_duplicate(path);
	endpoint->handler = handler;
	endpoint->param_names = NULL;
	endpoint->param_count = 0;
	endpoint->is_pattern = false;
	memset(&endpoint->regex, 0, sizeof(regex_t));

	compile_route_pattern(path, &endpoint->regex, &endpoint->param_names,
						  &endpoint->param_count, &endpoint->is_pattern);

	return endpoint;
}

void endpoint_destroy(struct EndPoint *endpoint) {
	if (endpoint) {
		free(endpoint->path);
		if (endpoint->is_pattern) {
			regfree(&endpoint->regex);
			for (size_t i = 0; i < endpoint->param_count; i++)
				free(endpoint->param_names[i]);
			free(endpoint->param_names);
		}
		free(endpoint);
	}
}

bool ends_with(const char *str, const char *suffix) {
	if (!str || !suffix)
		return false;
	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);
	if (suffix_len > str_len)
		return false;
	return strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0;
}

bool starts_with(const char *str, const char *prefix) {
	if (!str || !prefix)
		return false;
	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);
	if (prefix_len > str_len)
		return false;
	return strncmp(str, prefix, prefix_len) == 0;
}

char *str_duplicate(const char *str) {
	if (!str)
		return NULL;
	size_t len = strlen(str);
	char *dup = malloc(len + 1);
	if (!dup)
		return NULL;
	strcpy(dup, str);
	return dup;
}

// ThreadPool functions
void thread_pool_init(struct ThreadPool *pool, size_t thread_count) {
	if (!pool || thread_count == 0)
		return;
	pool->thread_count = thread_count;
	pool->threads = malloc(thread_count * sizeof(pthread_t));
	pool->task_queue_head = NULL;
	pool->task_queue_tail = NULL;
	pool->stop = false;
	pthread_mutex_init(&pool->lock, NULL);
	pthread_cond_init(&pool->cond, NULL);
	for (size_t i = 0; i < thread_count; i++) {
		pthread_create(&pool->threads[i], NULL, thread_pool_worker, pool);
	}
}

void thread_pool_destroy(struct ThreadPool *pool) {
	if (!pool)
		return;
	pthread_mutex_lock(&pool->lock);
	pool->stop = true;
	pthread_cond_broadcast(&pool->cond);
	pthread_mutex_unlock(&pool->lock);
	for (size_t i = 0; i < pool->thread_count; i++) {
		pthread_join(pool->threads[i], NULL);
	}
	free(pool->threads);
	while (pool->task_queue_head) {
		struct Task *task = pool->task_queue_head;
		pool->task_queue_head = task->next;
		if (task->arg_destroy) {
			task->arg_destroy(task->arg);
		}
		free(task);
	}
	pthread_mutex_destroy(&pool->lock);
	pthread_cond_destroy(&pool->cond);
}

void thread_pool_add_task(struct ThreadPool *pool, void (*function)(void *),
						  void *arg, void (*arg_destroy)(void *)) {
	if (!pool || !function)
		return;
	struct Task *task = malloc(sizeof(struct Task));
	if (!task)
		return;
	task->function = function;
	task->arg = arg;
	task->arg_destroy = arg_destroy;
	task->next = NULL;
	pthread_mutex_lock(&pool->lock);
	if (pool->task_queue_tail) {
		pool->task_queue_tail->next = task;
		pool->task_queue_tail = task;
	} else {
		pool->task_queue_head = task;
		pool->task_queue_tail = task;
	}
	pthread_cond_signal(&pool->cond);
	pthread_mutex_unlock(&pool->lock);
}

void *thread_pool_worker(void *arg) {
	struct ThreadPool *pool = (struct ThreadPool *)arg;
	while (1) {
		pthread_mutex_lock(&pool->lock);
		while (!pool->task_queue_head && !pool->stop) {
			pthread_cond_wait(&pool->cond, &pool->lock);
		}
		if (pool->stop) {
			pthread_mutex_unlock(&pool->lock);
			break;
		}
		struct Task *task = pool->task_queue_head;
		pool->task_queue_head = task->next;
		if (!pool->task_queue_head) {
			pool->task_queue_tail = NULL;
		}
		pthread_mutex_unlock(&pool->lock);
		task->function(task->arg);
		free(task);
	}
	return NULL;
}

size_t get_cpu_cores() { return sysconf(_SC_NPROCESSORS_ONLN); }

static char *url_decode_arena(Arena *arena, const char *str) {
	if (!str)
		return NULL;
	size_t len = strlen(str);
	char *decoded = arena_alloc(arena, len + 1);
	if (!decoded)
		return NULL;
	size_t i = 0, j = 0;
	while (i < len) {
		if (str[i] == '%' && i + 2 < len) {
			int hex_val;
			if (sscanf(&str[i + 1], "%2x", &hex_val) == 1) {
				decoded[j++] = (char)hex_val;
				i += 3;
			} else {
				decoded[j++] = str[i++];
			}
		} else if (str[i] == '+') {
			decoded[j++] = ' ';
			i++;
		} else {
			decoded[j++] = str[i++];
		}
	}
	decoded[j] = '\0';
	return decoded;
}

static void parse_query_parameters_arena(Arena *arena, struct Map *query_params,
										 const char *query_string) {
	if (!query_params || !query_string)
		return;

	char *query_copy = arena_str_duplicate(arena, query_string);
	if (!query_copy)
		return;

	char *saveptr;
	char *param = strtok_r(query_copy, "&", &saveptr);
	while (param) {
		char *equals = strchr(param, '=');
		if (equals) {
			*equals = '\0';
			char *key = url_decode_arena(arena, param);
			char *value = url_decode_arena(arena, equals + 1);
			if (key && value) {
				map_put(query_params, key, arena_str_duplicate(arena, value));
			}
		} else {
			char *key = url_decode_arena(arena, param);
			if (key) {
				map_put(query_params, key, "");
			}
		}
		param = strtok_r(NULL, "&", &saveptr);
	}
}

struct Request *parse_http_request(char *raw_request, Arena *arena) {
	if (!raw_request || !arena)
		return NULL;

	struct Request *request = arena_alloc(arena, sizeof(struct Request));
	if (!request)
		return NULL;

	request->method = HTTP_GET;
	request->path = NULL;
	request->body = NULL;
	request->headers = arena_alloc(arena, sizeof(struct Map));
	if (!request->headers)
		return NULL;
	map_init(request->headers, arena, 17);
	request->query_params = arena_alloc(arena, sizeof(struct Map));
	if (!request->query_params)
		return NULL;
	map_init(request->query_params, arena, 17);
	request->params = arena_alloc(arena, sizeof(struct Map));
	if (!request->params)
		return NULL;
	map_init(request->params, arena, 7);

	// In-place parsing: we modify raw_request
	char *request_ptr = raw_request;

	char *headers_end = strstr(request_ptr, "\r\n\r\n");
	if (!headers_end) {
		return NULL;
	}

	*headers_end = '\0';
	char *body_start = headers_end + 4;

	char *saveptr;
	char *line = strtok_r(request_ptr, "\r\n", &saveptr);
	if (!line) {
		return NULL;
	}

	char *method_str = strtok(line, " ");
	char *path_str = strtok(NULL, " ");
	char *version_str = strtok(NULL, " ");

	if (!method_str || !path_str || !version_str) {
		return NULL;
	}

	if (strcmp(method_str, "POST") == 0)
		request->method = HTTP_POST;
	else if (strcmp(method_str, "PUT") == 0)
		request->method = HTTP_PUT;
	else if (strcmp(method_str, "DELETE") == 0)
		request->method = HTTP_DELETE;
	else
		request->method = HTTP_GET;

	char *query_string = strchr(path_str, '?');
	if (query_string) {
		*query_string = '\0';
		parse_query_parameters_arena(arena, request->query_params,
									 query_string + 1);
	}
	// Use path_str directly as it is now null-terminated (either at ? or end of
	// string)
	request->path = path_str;

	while ((line = strtok_r(NULL, "\r\n", &saveptr))) {
		char *colon = strchr(line, ':');
		if (colon) {
			*colon = '\0';
			char *key = line;
			char *value = colon + 1;
			while (isspace(*value))
				value++;
			// Use key and value directly
			map_put(request->headers, key, value);
		}
	}

	char *content_length_str =
		(char *)map_get(request->headers, "Content-Length");
	if (content_length_str) {
		long content_length = atol(content_length_str);
		if (content_length > 0) {
			request->body = body_start;
		}
	}

	return request;
}

struct Response *create_http_response(int status_code, const char *body,
									  Arena *arena) {
	struct Response *response = arena_alloc(arena, sizeof(struct Response));
	if (!response)
		return NULL;

	response->status_code = status_code;
	response->body = arena_str_duplicate(arena, body ? body : "");
	response->headers = arena_alloc(arena, sizeof(struct Map));
	if (!response->headers)
		return NULL;
	map_init(response->headers, arena, 17);
	return response;
}

void send_http_response(int client_sock, struct Response *response) {
	if (!response || client_sock < 0)
		return;

	StringBuilder *sb = sb_create(NULL, 1024);

	const char *reason = "OK";
	switch (response->status_code) {
	case 201:
		reason = "Created";
		break;
	case 204:
		reason = "No Content";
		break;
	case 400:
		reason = "Bad Request";
		break;
	case 401:
		reason = "Unauthorized";
		break;
	case 403:
		reason = "Forbidden";
		break;
	case 404:
		reason = "Not Found";
		break;
	case 405:
		reason = "Method Not Allowed";
		break;
	case 500:
		reason = "Internal Server Error";
		break;
	}

	char status_line[256];
	sprintf(status_line, "HTTP/1.1 %d %s\r\n", response->status_code, reason);
	sb_append(sb, status_line);

	char content_length[256];
	sprintf(content_length, "Content-Length: %zu\r\n",
			strlen(response->body ? response->body : ""));
	sb_append(sb, content_length);

	bool has_content_type = false;
	if (response->headers) {
		for (size_t i = 0; i < response->headers->bucket_count; i++) {
			struct MapEntry *entry = response->headers->buckets[i];
			while (entry) {
				const char *k = entry->key;
				const char *v = (const char *)entry->value;
				if (k && v) {
					if (strcasecmp(k, "Content-Type") == 0) {
						has_content_type = true;
					}
					char header_line[1024];
					sprintf(header_line, "%s: %s\r\n", k, v);
					sb_append(sb, header_line);
				}
				entry = entry->next;
			}
		}
	}
	if (!has_content_type) {
		sb_append(sb, "Content-Type: text/plain; charset=utf-8\r\n");
	}

	sb_append(sb, "Connection: close\r\n\r\n");

	if (response->body) {
		sb_append(sb, response->body);
	}

	write(client_sock, sb->buffer, sb->length);
	sb_destroy(sb);
}