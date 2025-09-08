#pragma once

#include "common.h"

#include <pthread.h>

#define SERVER_DEFAULT_PORT 8080

struct Server {
	char *address;
	int port;
	int sockfd;
	pthread_mutex_t lock;

	struct ThreadPool
		*thread_pool; // Thread pool for handling client connections
	bool running;

	struct Map
		*endpoints; // Map of endpoints (key: path+method, value: EndPoint*)
};

void server_init(struct Server *server, const char *address, int port);
void server_destroy(struct Server *server);

void server_start(struct Server *server);
void server_stop(struct Server *server);

void server_add_endpoint(struct Server *server, struct EndPoint *endpoint);
void server_remove_endpoint(struct Server *server, const char *path,
							HttpMethod method);