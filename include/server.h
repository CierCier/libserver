#ifndef SERVER_H
#define SERVER_H

#include "common.h"

#include <pthread.h>

#define SERVER_DEFAULT_PORT 8080

// Middleware function signature. Middleware can optionally set a Response*
// (which short-circuits further processing) and/or set stop=true to halt the
// chain. user_data is provided at registration time. Arena is for memory
// allocation.
typedef void (*MiddlewareFunc)(struct Request *request,
							   struct Response **response, bool *stop,
							   void *user_data, Arena *arena);

struct MiddlewareNode {
	MiddlewareFunc fn;
	void *user_data;
	struct MiddlewareNode *next;
};

struct Router {
	struct Map *routes;				   // key: "method:/path" (relative path)
	struct MiddlewareNode *middleware; // router-level middleware chain
	Arena *arena;					   // arena for router allocations
};

struct Mount {
	char *base_path;	   // mount point (e.g., "/api")
	struct Router *router; // mounted router
	struct Mount *next;
};

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

	struct EndPoint *not_found_endpoint; // Custom 404 handler endpoint

	// New: global middleware chain and mounted routers
	struct MiddlewareNode *middleware; // global middleware
	struct Mount *mounts;			   // linked list of mounts

	// SSL Context
	void *ssl_ctx; // cast to SSL_CTX* in implementation
	bool use_ssl;

	Arena *arena; // arena for server allocations
};

void server_init(struct Server *server, const char *address, int port);
void server_destroy(struct Server *server);

void server_start(struct Server *server);
void server_stop(struct Server *server);

void server_add_endpoint(struct Server *server, HttpMethod method,
						 const char *path, RequestHandler handler);
void server_remove_endpoint(struct Server *server, const char *path,
							HttpMethod method);

// Global middleware
void server_use(struct Server *server, MiddlewareFunc fn, void *user_data);

// Routers API
struct Router *router_create(void);
void router_destroy(struct Router *router);
void router_use(struct Router *router, MiddlewareFunc fn, void *user_data);
void router_add(struct Router *router, HttpMethod method, const char *path,
				RequestHandler handler);

// Mount a router at a base path (prefix). Paths in the router are matched
// relative to this base. E.g., mount "/api" and add route "/users" →
// matches request path "/api/users".
void server_mount_router(struct Server *server, const char *base_path,
						 struct Router *router);

void server_enable_https(struct Server *server, const char *cert_path,
						 const char *key_path);

#endif // SERVER_H
