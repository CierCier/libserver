#pragma once

#include <pthread.h>
#include <regex.h>
#include <stdbool.h>
#include <stddef.h>

#define KB(x) (x << 10)
#define MB(x) (x << 20)
#define GB(x) (x << 30)

typedef enum { HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE } HttpMethod;

struct Request {
	HttpMethod method;
	char *path;
	char *body;
	struct Map
		*headers; // Map of headers (key: header name, value: header value)
	struct Map *query_params; // Map of query parameters (key: param name,
							  // value: param value)
	struct Map *params;		  // Map of path parameters (e.g., id -> "123")
};

struct Response {
	int status_code;
	char *body;
	struct Map
		*headers; // Map of headers (key: header name, value: header value)
};

/*
 * Function pointer type for request handlers
 * @param const char* - The request data (e.g., URL, headers, body)
 * @return struct Response* - The response data (e.g., status code, headers,
 * body)
 */
typedef struct Response *(*RequestHandler)(struct Request *request);

struct EndPoint {
	HttpMethod method;
	char *path;				// original pattern, e.g., "/user/:id"
	RequestHandler handler; // user handler

	// Compiled regex and parameter metadata derived from path
	regex_t regex;		// e.g., ^/user/([^/]+)$
	char **param_names; // ["id", ...]
	size_t param_count; // number of capture groups
	bool is_pattern;	// true if path contains ':' params
};

/*
 * Creates a new endpoint
 * @param HttpMethod - The HTTP method for the endpoint
 * @param const char* - The path for the endpoint
 * @param RequestHandler - The function to handle requests to the endpoint
 * @return struct EndPoint* - A pointer to the newly created endpoint
 */
struct EndPoint *endpoint_create(HttpMethod method, const char *path,
								 RequestHandler handler);

/*
 * Destroys an endpoint, freeing its resources
 * @param struct EndPoint* - The endpoint to destroy
 */
void endpoint_destroy(struct EndPoint *endpoint);

bool ends_with(const char *str, const char *suffix);
bool starts_with(const char *str, const char *prefix);

/*
 * Duplicates a string
 * @param const char* - The string to duplicate
 * @return char* - A new string that is a duplicate of the input
 */
char *str_duplicate(const char *str);

// ThreadPool
struct ThreadPool {
	pthread_t *threads;
	size_t thread_count;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct Task *task_queue_head;
	struct Task *task_queue_tail;
	bool stop;
};

struct Task {
	void (*function)(void *);
	void *arg;
	struct Task *next;
};

void thread_pool_init(struct ThreadPool *pool, size_t thread_count);
void thread_pool_destroy(struct ThreadPool *pool);
void thread_pool_add_task(struct ThreadPool *pool, void (*function)(void *),
						  void *arg);

void *thread_pool_worker(void *arg);

size_t get_cpu_cores();

struct Request *parse_http_request(const char *raw_request);
void free_http_request(struct Request *request);

struct Response *create_http_response(int status_code, const char *body);
void free_http_response(struct Response *response);

void send_http_response(int client_sock, struct Response *response);
