#include <json.h>
#include <log.h>
#include <map.h>
#include <server.h>
#include <stdio.h>
#include <stdlib.h>
#include <stringbuilder.h>

static void logger_mw(struct Request *req, struct Response **res, bool *stop,
					  void *user_data, Arena *arena) {
	(void)user_data;
	(void)arena;
	(void)res;
	app_log(LOG_LEVEL_INFO, "Incoming %d %s", req->method, req->path);
	(void)stop; // allow chain to continue
}

static void json_mw(struct Request *req, struct Response **res, bool *stop,
					void *user_data, Arena *arena) {
	(void)req;
	(void)user_data;
	(void)stop;
	(void)arena;
	// Force JSON content-type if a response is produced later by handler
	if (*res && (*res)->headers) {
		(void)map_put((*res)->headers, "Content-Type",
					  "application/json; charset=utf-8");
	}
}

// Helper to build a tiny JSON string without full json builder (keep
// dependencies minimal)
static struct Response *json_response(int status, const char *json,
									  Arena *arena) {
	struct Response *r = create_http_response(status, json, arena);
	(void)map_put(r->headers, "Content-Type",
				  "application/json; charset=utf-8");
	return r;
}

static struct Response *hello_handler(struct Request *req, Arena *arena) {
	(void)req;
	return json_response(200, "{\"message\":\"hello from API\"}", arena);
}

static struct Response *echo_query_handler(struct Request *req, Arena *arena) {
	// returns query params as a naive JSON object string for demo
	// WARNING: no escaping for brevity
	StringBuilder *sb = sb_create(arena, 0);
	sb_append(sb, "{");
	bool first = true;
	for (size_t i = 0; i < req->query_params->bucket_count; i++) {
		struct MapEntry *e = req->query_params->buckets[i];
		while (e) {
			if (!first)
				sb_append(sb, ",");
			first = false;
			// no formatted append in sb API; build manually
			sb_append(sb, "\"");
			sb_append(sb, e->key);
			sb_append(sb, "\":\"");
			sb_append(sb, (char *)e->value);
			sb_append(sb, "\"");
			e = e->next;
		}
	}
	sb_append(sb, "}");
	char *json = sb_to_string(sb);
	sb_destroy(sb);
	struct Response *r = json_response(200, json, arena);
	return r;
}

#include "protocols/ftp_http.h"

static void ftp_middleware(struct Request *req, struct Response **res,
						   bool *stop, void *user_data, Arena *arena) {
	(void)user_data;
	if (starts_with(req->path, "/ftp")) {
		char *original_path = req->path;
		// Strip /ftp. If path is just /ftp, it becomes empty string, map to /
		const char *subpath = req->path + 4;
		if (*subpath == '\0')
			subpath = "/";

		req->path = arena_str_duplicate(arena, subpath);
		*res = ftp_http_handler(req, arena);
		req->path = original_path;
		*stop = true;
	}
}

int main() {
	struct Server server;
	server_init(&server, "127.0.0.1", SERVER_DEFAULT_PORT);

	// Initialize FTP driver
	// Root: current directory (.)
	// CSS: examples/ftp_server/style.css
	ftp_driver_init(".", "examples/ftp_server/style.css");

	// Global middleware
	server_use(&server, logger_mw, NULL);
	server_use(&server, ftp_middleware, NULL);

	// Create router and add routes
	struct Router *api = router_create();
	router_use(api, json_mw, NULL); // router-level mw
	router_add(api, HTTP_GET, "/hello", hello_handler);
	router_add(api, HTTP_GET, "/echo", echo_query_handler);

	// Mount router at /api
	server_mount_router(&server, "/api", api);

	// Also add a root endpoint without router
	server_add_endpoint(&server, HTTP_GET, "/", hello_handler);

	server_start(&server);
	server_destroy(&server);
	return 0;
}
