#include "log.h"
#include "map.h"
#include <arpa/inet.h>
#include <server.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void handle_client(void *arg) {
	if (!arg)
		return;

	void **args = (void **)arg;
	struct Server *server = (struct Server *)args[0];
	int client_sock = *(int *)args[1];

	free(args[1]);
	free(arg);

	char buffer[4096];
	memset(buffer, 0, sizeof(buffer));
	ssize_t bytes_read = read(client_sock, buffer, sizeof(buffer) - 1);
	if (bytes_read < 0) {
		perror("read");
		close(client_sock);
		return;
	}

	struct Request *request = parse_http_request(buffer);
	if (!request) {
		app_log(LOG_LEVEL_ERROR, "Failed to parse HTTP request");
		close(client_sock);
		return;
	}

	// Create a unique key for the endpoint based on method and path
	char key[256];
	snprintf(key, sizeof(key), "%d:%s", request->method, request->path);

	struct EndPoint *endpoint =
		(struct EndPoint *)map_get(server->endpoints, key);
	struct Response *response = NULL;
	if (endpoint && endpoint->handler) {
		app_log(LOG_LEVEL_INFO, "Handling request for %s", request->path);
		response = endpoint->handler(request);
	} else {
		app_log(LOG_LEVEL_WARNING, "No handler for %s, using 404",
				request->path);
		if (server->not_found_endpoint && server->not_found_endpoint->handler) {
			response = server->not_found_endpoint->handler(request);
		} else {
			response = create_http_response(404, "Not Found");
		}
	}
	if (!response) {
		app_log(LOG_LEVEL_ERROR, "Handler returned NULL response, %s",
				request->path);

		response = create_http_response(500, "Internal Server Error");
	}

	send_http_response(client_sock, response);

	free_http_request(request);
	free_http_response(response);
	close(client_sock);
}

static struct Response *__not_found_handler_default(struct Request *request) {
	(void)request;
	return create_http_response(404, "Not Found");
}

void server_init(struct Server *server, const char *address, int port) {
	if (!server)
		return;

	server->address = str_duplicate(address ? address : "localhost");
	server->port = port;
	server->sockfd = -1;
	pthread_mutex_init(&server->lock, NULL);

	server->thread_pool = malloc(sizeof(struct ThreadPool));
	thread_pool_init(server->thread_pool, get_cpu_cores());

	server->running = false;

	server->endpoints = malloc(sizeof(struct Map));
	map_init(server->endpoints, 53);

	server->not_found_endpoint =
		endpoint_create(HTTP_GET, "/404", __not_found_handler_default);
}

void server_destroy(struct Server *server) {
	if (!server)
		return;

	server_stop(server);

	free(server->address);
	pthread_mutex_destroy(&server->lock);

	thread_pool_destroy(server->thread_pool);
	free(server->thread_pool);

	// Free all endpoints
	for (size_t i = 0; i < server->endpoints->bucket_count; i++) {
		struct MapEntry *entry = server->endpoints->buckets[i];
		while (entry) {
			struct EndPoint *endpoint = (struct EndPoint *)entry->value;
			endpoint_destroy(endpoint);
			entry = entry->next;
		}
	}

	map_destroy(server->endpoints);
	free(server->endpoints);
}

void server_start(struct Server *server) {
	if (!server || server->running)
		return;

	// Create socket
	server->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (server->sockfd < 0) {
		app_log(LOG_LEVEL_ERROR, "Failed to create socket");
		return;
	}

	// Allow quick reuse of the address/port
	int opt = 1;
	if (setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt,
				   sizeof(opt)) < 0) {
		app_log(LOG_LEVEL_WARNING, "setsockopt(SO_REUSEADDR) failed");
	}

	// Bind socket
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(server->address);
	serv_addr.sin_port = htons(server->port);

	if (bind(server->sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) <
		0) {
		app_log(LOG_LEVEL_ERROR, "Failed to bind socket");
		close(server->sockfd);
		return;
	}

	// Listen for connections
	if (listen(server->sockfd, 5) < 0) {
		app_log(LOG_LEVEL_ERROR, "Failed to listen on socket");
		close(server->sockfd);
		return;
	}

	server->running = true;
	printf("Server started on %s:%d\n", server->address, server->port);

	// Main accept loop

	while (server->running) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		int newsockfd = accept(server->sockfd, (struct sockaddr *)&client_addr,
							   &client_len);
		if (newsockfd < 0) {
			if (server->running) {
				perror("accept");
			}
			continue;
		}

		// Handle connection in thread pool
		int *pclient = malloc(sizeof(int));
		*pclient = newsockfd;
		void **args = malloc(2 * sizeof(void *));
		args[0] = (void *)server;
		args[1] = (void *)pclient;
		thread_pool_add_task(server->thread_pool, handle_client, args);
	}

	close(server->sockfd);
	server->sockfd = -1;
}

void server_stop(struct Server *server) {
	if (!server || !server->running)
		return;

	pthread_mutex_lock(&server->lock);
	server->running = false;
	pthread_mutex_unlock(&server->lock);

	if (server->sockfd >= 0) {
		close(server->sockfd);
		server->sockfd = -1;
	}
}

void server_add_endpoint(struct Server *server, struct EndPoint *endpoint) {
	if (!server || !endpoint)
		return;

	// Create a unique key for the endpoint based on method and path
	char key[256];
	snprintf(key, sizeof(key), "%d:%s", endpoint->method, endpoint->path);

	map_put(server->endpoints, key, endpoint);
}

void server_remove_endpoint(struct Server *server, const char *path,
							HttpMethod method) {
	if (!server || !path)
		return;

	char key[256];
	snprintf(key, sizeof(key), "%d:%s", method, path);

	struct EndPoint *endpoint =
		(struct EndPoint *)map_get(server->endpoints, key);
	if (endpoint) {
		endpoint_destroy(endpoint);
		map_remove(server->endpoints, key);
	}
}