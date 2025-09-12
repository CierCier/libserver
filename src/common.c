// Efficiently stream a file to a socket (returns 0 on success, -1 on error)
#include "common.h"
#include "map.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct EndPoint *endpoint_create(HttpMethod method, const char *path,
								 RequestHandler handler) {
	struct EndPoint *endpoint = malloc(sizeof(struct EndPoint));
	if (!endpoint)
		return NULL;

	endpoint->method = method;
	endpoint->path = str_duplicate(path);
	endpoint->handler = handler;

	return endpoint;
}

void endpoint_destroy(struct EndPoint *endpoint) {
	if (endpoint) {
		free(endpoint->path);
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

	// Free remaining tasks
	while (pool->task_queue_head) {
		struct Task *task = pool->task_queue_head;
		pool->task_queue_head = task->next;
		free(task);
	}

	pthread_mutex_destroy(&pool->lock);
	pthread_cond_destroy(&pool->cond);
}

void thread_pool_add_task(struct ThreadPool *pool, void (*function)(void *),
						  void *arg) {
	if (!pool || !function)
		return;

	struct Task *task = malloc(sizeof(struct Task));
	if (!task)
		return;

	task->function = function;
	task->arg = arg;
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

// Helper function to URL decode a string
char *url_decode(const char *str) {
	if (!str)
		return NULL;

	size_t len = strlen(str);
	char *decoded = malloc(len + 1);
	if (!decoded)
		return NULL;

	size_t i = 0, j = 0;
	while (i < len) {
		if (str[i] == '%' && i + 2 < len) {
			// Decode hex value
			int hex_val;
			if (sscanf(&str[i + 1], "%2x", &hex_val) == 1) {
				decoded[j++] = (char)hex_val;
				i += 3;
			} else {
				decoded[j++] = str[i++];
			}
		} else if (str[i] == '+') {
			// Replace + with space
			decoded[j++] = ' ';
			i++;
		} else {
			decoded[j++] = str[i++];
		}
	}
	decoded[j] = '\0';
	return decoded;
}

// Helper function to parse query parameters
void parse_query_parameters(struct Map *query_params,
							const char *query_string) {
	if (!query_params || !query_string)
		return;

	char *query_copy = str_duplicate(query_string);
	if (!query_copy)
		return;

	char *param = strtok(query_copy, "&");
	while (param) {
		char *equals = strchr(param, '=');
		if (equals) {
			*equals = '\0'; // Split key from value
			char *key = url_decode(param);
			char *value = url_decode(equals + 1);

			if (key && value) {
				map_put(query_params, key, str_duplicate(value));
			}

			free(key);
			free(value);
		} else {
			// Parameter without value (e.g., ?debug)
			char *key = url_decode(param);
			if (key) {
				map_put(query_params, key, str_duplicate(""));
				free(key);
			}
		}
		param = strtok(NULL, "&");
	}

	free(query_copy);
}

struct Request *parse_http_request(const char *raw_request) {
	if (!raw_request)
		return NULL;

	struct Request *request = malloc(sizeof(struct Request));
	if (!request)
		return NULL;

	// Initialize with defaults
	request->method = HTTP_GET;
	request->path = str_duplicate("/");
	request->body = NULL;
	request->headers = malloc(sizeof(struct Map));
	map_init(request->headers, 17);
	request->query_params = malloc(sizeof(struct Map));
	map_init(request->query_params, 17);

	// Parse the request line (first line)
	char *request_copy = str_duplicate(raw_request);
	if (!request_copy) {
		free_http_request(request);
		return NULL;
	}

	char *line = strtok(request_copy, "\r\n");
	if (!line) {
		free(request_copy);
		free_http_request(request);
		return NULL;
	}

	// Parse method, path, and version
	char *method_str = strtok(line, " ");
	char *path_str = strtok(NULL, " ");
	char *version_str = strtok(NULL, " ");

	if (!method_str || !path_str || !version_str) {
		free(request_copy);
		free_http_request(request);
		return NULL;
	}

	// Parse HTTP method
	if (strcmp(method_str, "GET") == 0) {
		request->method = HTTP_GET;
	} else if (strcmp(method_str, "POST") == 0) {
		request->method = HTTP_POST;
	} else if (strcmp(method_str, "PUT") == 0) {
		request->method = HTTP_PUT;
	} else if (strcmp(method_str, "DELETE") == 0) {
		request->method = HTTP_DELETE;
	} else {
		request->method = HTTP_GET; // Default to GET
	}

	// Parse path and query parameters
	free(request->path);
	char *query_start = strchr(path_str, '?');
	if (query_start) {
		*query_start = '\0'; // Split path from query
		query_start++;		 // Move past '?'

		// Parse query parameters
		parse_query_parameters(request->query_params, query_start);
	}
	request->path = str_duplicate(path_str);

	free(request_copy);
	return request;
}

void free_http_request(struct Request *request) {
	if (!request)
		return;

	free(request->path);
	free(request->body);

	// Free all query parameter values before destroying the map
	if (request->query_params) {
		for (size_t i = 0; i < request->query_params->bucket_count; i++) {
			struct MapEntry *entry = request->query_params->buckets[i];
			while (entry) {
				free(entry->value); // Free the duplicated value string
				entry = entry->next;
			}
		}
		map_destroy(request->query_params);
		free(request->query_params);
	}

	// Clean up headers map
	if (request->headers) {
		map_destroy(request->headers);
		free(request->headers);
	}

	free(request);
}

struct Response *create_http_response(int status_code, const char *body) {
	struct Response *response = malloc(sizeof(struct Response));
	if (!response)
		return NULL;

	response->status_code = status_code;
	response->body = str_duplicate(body ? body : "");
	response->headers = malloc(sizeof(struct Map));
	map_init(response->headers, 17);
	return response;
}

void free_http_response(struct Response *response) {
	if (!response)
		return;
	free(response->body);
	map_destroy(response->headers);
	free(response);
}

void send_http_response(int client_sock, struct Response *response) {
	if (!response || client_sock < 0)
		return;

	// Simple HTTP response format
	const char *reason = "OK";
	switch (response->status_code) {
	case 200:
		reason = "OK";
		break;
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
	default:
		reason = "OK";
		break;
	}

	char status_line[256];
	snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d %s\r\n",
			 response->status_code, reason);
	write(client_sock, status_line, strlen(status_line));

	// Content-Length header
	char content_length[256];
	snprintf(content_length, sizeof(content_length), "Content-Length: %zu\r\n",
			 strlen(response->body ? response->body : ""));
	write(client_sock, content_length, strlen(content_length));

	// Default Content-Type header (text/plain; charset=utf-8)
	const char *content_type = "Content-Type: text/plain; charset=utf-8\r\n";
	write(client_sock, content_type, strlen(content_type));

	// Indicate we will close the connection
	const char *conn_close = "Connection: close\r\n";
	write(client_sock, conn_close, strlen(conn_close));

	// End headers
	write(client_sock, "\r\n", 2);

	// Body
	if (response->body) {
		write(client_sock, response->body, strlen(response->body));
	}
}
