#include "arena.h"
#include "common.h"
#include "http2.h"
#include "log.h"
#include "map.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <server.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Global pointer for signal handler to access the running server
static struct Server *g_server_instance = NULL;
static struct sigaction g_old_sigint_action;
static struct sigaction g_old_sigterm_action;

static void signal_handler(int sig) {
	if (g_server_instance) {
		app_log(LOG_LEVEL_INFO, "Received signal %d, shutting down server...",
				sig);
		server_stop(g_server_instance);
	}
}

static void run_middleware_chain(struct MiddlewareNode *head,
								 struct Request *req, struct Response **resp,
								 Arena *arena) {
	bool stop = false;
	struct MiddlewareNode *cur = head;
	while (cur && !stop && (!(*resp))) {
		cur->fn(req, resp, &stop, cur->user_data, arena);
		cur = cur->next;
	}
}

static struct Response *dispatch_to_endpoint(struct EndPoint *endpoint,
											 struct Request *request,
											 Arena *arena) {
	if (endpoint && endpoint->handler) {
		app_log(LOG_LEVEL_INFO, "Handling request for %s", request->path);
		return endpoint->handler(request, arena);
	}
	return NULL;
}

static struct EndPoint *match_endpoint_in_map(struct Map *routes,
											  HttpMethod method,
											  const char *path_key,
											  struct Request *request,
											  Arena *arena) {
	if (!routes)
		return NULL;
	// 1) try exact match first
	char key[256];
	snprintf(key, sizeof(key), "%d:%s", method, path_key);
	struct EndPoint *ep_exact = (struct EndPoint *)map_get(routes, key);
	if (ep_exact)
		return ep_exact;

	// 2) scan for pattern endpoints of same method and test regex
	for (size_t i = 0; i < routes->bucket_count; i++) {
		struct MapEntry *e = routes->buckets[i];
		while (e) {
			struct EndPoint *ep = (struct EndPoint *)e->value;
			if (ep && ep->method == method && ep->is_pattern) {
				regmatch_t pm[ep->param_count + 1];
				if (regexec(&ep->regex, path_key, ep->param_count + 1, pm, 0) ==
					0) {
					// Fill request->params from capture groups
					for (size_t k = 0; k < ep->param_count; k++) {
						int start = pm[k + 1].rm_so;
						int end = pm[k + 1].rm_eo;
						if (start >= 0 && end >= start) {
							size_t plen = (size_t)(end - start);
							char *val = arena_alloc(arena, plen + 1);
							memcpy(val, path_key + start, plen);
							val[plen] = '\0';
							map_put(request->params, ep->param_names[k], val);
						}
					}
					return ep;
				}
			}
			e = e->next;
		}
	}
	return NULL;
}

static struct EndPoint *match_mounted_router(struct Server *server,
											 struct Request *request,
											 struct Router **out_router,
											 Arena *arena) {
	struct Mount *m = server->mounts;
	size_t best_len = 0;
	struct EndPoint *best_ep = NULL;
	struct Router *best_router = NULL;
	while (m) {
		if (starts_with(request->path, m->base_path)) {
			size_t base_len = strlen(m->base_path);
			// Compute relative path (ensure leading slash semantics)
			const char *rel = request->path + base_len;
			if (*rel == '\0')
				rel = "/"; // exact mount path -> root within router
			// Match within router (relative path)
			struct EndPoint *ep = match_endpoint_in_map(
				m->router->routes, request->method, rel, request, arena);
			if (ep && base_len > best_len) {
				best_len = base_len;
				best_ep = ep;
				best_router = m->router;
			}
		}
		m = m->next;
	}
	if (out_router)
		*out_router = best_router;
	return best_ep;
}

#define REQ_BUFFER_SIZE 65536
void handle_client(void *arg) {
	if (!arg)
		return;

	void **args = (void **)arg;
	struct Server *server = (struct Server *)args[0];
	int client_sock = *(int *)args[1];

	Arena *arena = arena_create();
	if (!arena) {
		close(client_sock);
		return;
	}

	SSL *ssl = NULL;
	if (server->use_ssl && server->ssl_ctx) {
		ssl = SSL_new((SSL_CTX *)server->ssl_ctx);
		SSL_set_fd(ssl, client_sock);
		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
			SSL_free(ssl);
			close(client_sock);
			arena_destroy(arena);
			return;
		}
	}

	char buffer[REQ_BUFFER_SIZE];
	memset(buffer, 0, sizeof(buffer));

	ssize_t bytes_read;
	if (ssl) {

		const unsigned char *alpn = NULL;
		unsigned int alpnlen = 0;
		SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
		if (alpn && alpnlen == 2 && memcmp(alpn, "h2", 2) == 0) {
			app_log(LOG_LEVEL_INFO, "Negotiated HTTP/2");
			handle_http2_session(server, client_sock, ssl);
			// Clean up and return, session handled
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(client_sock);
			arena_destroy(arena);
			return;
		}

		bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
	} else {

		bytes_read = read(client_sock, buffer, sizeof(buffer) - 1);
	}

	if (bytes_read < 0) {
		perror("read");
		if (ssl)
			SSL_free(ssl);
		close(client_sock);
		arena_destroy(arena);
		return;
	}

	struct Request *request = parse_http_request(buffer, arena);
	if (!request) {
		app_log(LOG_LEVEL_ERROR, "Failed to parse HTTP request");
		if (ssl)
			SSL_free(ssl);
		close(client_sock);
		arena_destroy(arena);
		return;
	}

	struct Response *response = NULL;

	// Run global middleware first (can short-circuit)
	if (server->middleware) {
		run_middleware_chain(server->middleware, request, &response, arena);
	}

	struct Router *matched_router = NULL;
	struct EndPoint *endpoint = NULL;

	if (!response) {
		// Try server-level match (exact or pattern)
		endpoint = match_endpoint_in_map(server->endpoints, request->method,
										 request->path, request, arena);

		// If not found, try mounted routers
		if (!endpoint) {
			endpoint =
				match_mounted_router(server, request, &matched_router, arena);
		}

		// If router matched, run router-level middleware before handler
		if (matched_router && matched_router->middleware) {
			run_middleware_chain(matched_router->middleware, request, &response,
								 arena);
		}

		if (!response) {
			response = dispatch_to_endpoint(endpoint, request, arena);
		}
	}

	if (!response) {
		app_log(LOG_LEVEL_WARNING, "No handler for %s, using 404",
				request->path);
		if (server->not_found_endpoint && server->not_found_endpoint->handler) {
			response = server->not_found_endpoint->handler(request, arena);
		} else {
			response = create_http_response(404, "Not Found", arena);
		}
	}
	if (!response) {
		app_log(LOG_LEVEL_ERROR, "Handler returned NULL response, %s",
				request->path);

		response = create_http_response(500, "Internal Server Error", arena);
	}

	send_http_response(client_sock, ssl, response);
	app_log(LOG_LEVEL_INFO, "Response sent");

	if (ssl) {
		// SSL_shutdown(ssl); // skip shutdown for now to see if it fixes curl
		// error
		SSL_free(ssl);
	}
	arena_destroy(arena);
	close(client_sock);
}
static struct Response *__not_found_handler_default(struct Request *request,
													Arena *arena) {
	(void)request;
	return create_http_response(404, "Not Found", arena);
}

void server_init(struct Server *server, const char *address, int port) {
	if (!server)
		return;

	server->arena = arena_create();
	if (!server->arena)
		return;

	server->address =
		arena_str_duplicate(server->arena, address ? address : "localhost");
	server->port = port;
	server->sockfd = -1;
	pthread_mutex_init(&server->lock, NULL);

	server->thread_pool = malloc(sizeof(struct ThreadPool));

	int thread_count = get_cpu_cores();
#ifdef _MIN_THREAD_COUNT
	if (thread_count < _MIN_THREAD_COUNT)
		thread_count = _MIN_THREAD_COUNT;
#endif

	thread_pool_init(server->thread_pool, thread_count);
	app_log(LOG_LEVEL_INFO, "Initialized thread pool with %zu threads",
			server->thread_pool->thread_count);

	server->running = false;

	server->endpoints = arena_alloc(server->arena, sizeof(struct Map));
	map_init(server->endpoints, server->arena, 53);

	server->not_found_endpoint =
		endpoint_create(HTTP_GET, "/404", __not_found_handler_default);

	server->middleware = NULL;
	server->mounts = NULL;
	server->ssl_ctx = NULL;
	server->use_ssl = false;
	server->ssl_ctx = NULL;
	server->use_ssl = false;
}

void server_destroy(struct Server *server) {
	if (!server)
		return;

	if (server->use_ssl && server->ssl_ctx) {
		SSL_CTX_free((SSL_CTX *)server->ssl_ctx);
	}

	server_stop(server);

	// server->address is arena-allocated, no need to free
	pthread_mutex_destroy(&server->lock);

	thread_pool_destroy(server->thread_pool);
	free(server->thread_pool);

	// Free all endpoints (endpoint_destroy uses malloc internally)
	for (size_t i = 0; i < server->endpoints->bucket_count; i++) {
		struct MapEntry *entry = server->endpoints->buckets[i];
		while (entry) {
			struct EndPoint *endpoint = (struct EndPoint *)entry->value;
			endpoint_destroy(endpoint);
			entry = entry->next;
		}
	}

	map_destroy(server->endpoints);
	// server->endpoints is arena-allocated, no need to free
	endpoint_destroy(server->not_found_endpoint);

	// Middleware nodes are still malloc'd, free them
	struct MiddlewareNode *mn = server->middleware;
	while (mn) {
		struct MiddlewareNode *next = mn->next;
		free(mn);
		mn = next;
	}

	// Free mounts and routers
	struct Mount *mt = server->mounts;
	while (mt) {
		struct Mount *next = mt->next;
		// mt->base_path is arena-allocated, handled by router_destroy's arena
		router_destroy(mt->router);
		free(mt);
		mt = next;
	}

	// Destroy the arena last - this frees all arena-allocated memory
	arena_destroy(server->arena);
}

static void handle_client_arg_destroy(void *arg) {
	if (!arg)
		return;
	void **args = (void **)arg;
	free(args[1]);
	free(args);
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

	// Set up signal handlers for graceful shutdown
	g_server_instance = server;
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, &g_old_sigint_action);
	sigaction(SIGTERM, &sa, &g_old_sigterm_action);

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
		thread_pool_add_task(server->thread_pool, handle_client, args,
							 handle_client_arg_destroy);
	}

	// Restore original signal handlers
	sigaction(SIGINT, &g_old_sigint_action, NULL);
	sigaction(SIGTERM, &g_old_sigterm_action, NULL);
	g_server_instance = NULL;

	close(server->sockfd);
	server->sockfd = -1;
	printf("Server stopped\n");
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

void server_add_endpoint(struct Server *server, HttpMethod method,
						 const char *path, RequestHandler handler) {
	if (!server || !path)
		return;

	struct EndPoint *endpoint = endpoint_create(method, path, handler);

	char key[256];
	snprintf(key, sizeof(key), "%d:%s", method, path);

	struct EndPoint *old_endpoint =
		(struct EndPoint *)map_put(server->endpoints, key, endpoint);
	if (old_endpoint) {
		endpoint_destroy(old_endpoint);
	}
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

// Public API: middleware and routers
void server_use(struct Server *server, MiddlewareFunc fn, void *user_data) {
	if (!server || !fn)
		return;
	struct MiddlewareNode *node = malloc(sizeof(struct MiddlewareNode));
	node->fn = fn;
	node->user_data = user_data;
	node->next = NULL;
	if (!server->middleware) {
		server->middleware = node;
	} else {
		struct MiddlewareNode *cur = server->middleware;
		while (cur->next)
			cur = cur->next;
		cur->next = node;
	}
}

struct Router *router_create(void) {
	struct Router *r = malloc(sizeof(struct Router));
	if (!r)
		return NULL;
	r->arena = arena_create();
	if (!r->arena) {
		free(r);
		return NULL;
	}
	r->routes = arena_alloc(r->arena, sizeof(struct Map));
	map_init(r->routes, r->arena, 53);
	r->middleware = NULL;
	return r;
}

void router_destroy(struct Router *router) {
	if (!router)
		return;
	// free endpoints inside routes map (they use malloc internally)
	for (size_t i = 0; i < router->routes->bucket_count; i++) {
		struct MapEntry *entry = router->routes->buckets[i];
		while (entry) {
			struct EndPoint *endpoint = (struct EndPoint *)entry->value;
			endpoint_destroy(endpoint);
			entry = entry->next;
		}
	}
	map_destroy(router->routes);
	// router->routes is arena-allocated, no need to free
	// free middleware (still uses malloc)
	struct MiddlewareNode *mn = router->middleware;
	while (mn) {
		struct MiddlewareNode *next = mn->next;
		free(mn);
		mn = next;
	}
	// Destroy the arena - this frees all arena-allocated memory
	arena_destroy(router->arena);
	free(router);
}

void router_use(struct Router *router, MiddlewareFunc fn, void *user_data) {
	if (!router || !fn)
		return;
	struct MiddlewareNode *node = malloc(sizeof(struct MiddlewareNode));
	node->fn = fn;
	node->user_data = user_data;
	node->next = NULL;
	if (!router->middleware) {
		router->middleware = node;
	} else {
		struct MiddlewareNode *cur = router->middleware;
		while (cur->next)
			cur = cur->next;
		cur->next = node;
	}
}

void router_add(struct Router *router, HttpMethod method, const char *path,
				RequestHandler handler) {
	if (!router || !path)
		return;
	struct EndPoint *endpoint = endpoint_create(method, path, handler);
	char key[256];
	snprintf(key, sizeof(key), "%d:%s", method, path);
	struct EndPoint *old_endpoint =
		(struct EndPoint *)map_put(router->routes, key, endpoint);
	if (old_endpoint) {
		endpoint_destroy(old_endpoint);
	}
}

void server_mount_router(struct Server *server, const char *base_path,
						 struct Router *router) {
	if (!server || !base_path || !router)
		return;
	struct Mount *m = malloc(sizeof(struct Mount));
	m->base_path = str_duplicate(base_path);
	m->router = router;
	m->next = NULL;
	if (!server->mounts) {
		server->mounts = m;
	} else {
		struct Mount *cur = server->mounts;
		while (cur->next)
			cur = cur->next;
		cur->next = m;
	}
}

static int alpn_select_cb(SSL *ssl, const unsigned char **out,
						  unsigned char *outlen, const unsigned char *in,
						  unsigned int inlen, void *arg) {
	unsigned char *protos = (unsigned char *)"\x02h2\x08http/1.1";
	unsigned int protos_len = 12;

	if (SSL_select_next_proto((unsigned char **)out, outlen, protos, protos_len,
							  in, inlen) != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	return SSL_TLSEXT_ERR_OK;
}

void server_enable_https(struct Server *server, const char *cert_path,
						 const char *key_path) {

	if (!server || !cert_path || !key_path)
		return;

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) {
		app_log(LOG_LEVEL_ERROR, "Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		return;
	}

	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION); // Keep TLS 1.2 minimum
	SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);

	if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
		app_log(LOG_LEVEL_ERROR, "Failed to load certificate file");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		return;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
		app_log(LOG_LEVEL_ERROR, "Failed to load private key file");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		return;
	}

	server->ssl_ctx = ctx;
	server->use_ssl = true;
	app_log(LOG_LEVEL_INFO, "HTTPS enabled");
}
