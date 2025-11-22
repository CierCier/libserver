#include <json.h>
#include <log.h>
#include <map.h>
#include <server.h>
#include <stdio.h>
#include <stdlib.h>
#include <stringbuilder.h>

static void logger_mw(struct Request *req, struct Response **res, bool *stop,
					  void *user_data) {
	(void)user_data;
	app_log(LOG_LEVEL_INFO, "Incoming %d %s", req->method, req->path);
	(void)stop; // allow chain to continue
}

static void json_mw(struct Request *req, struct Response **res, bool *stop,
					void *user_data) {
	(void)req;
	(void)user_data;
	(void)stop;
	// Force JSON content-type if a response is produced later by handler
	if (*res && (*res)->headers) {
		map_put((*res)->headers, "Content-Type",
				"application/json; charset=utf-8");
	}
}

// Helper to build a tiny JSON string without full json builder (keep
// dependencies minimal)
static struct Response *json_response(int status, const char *json) {
	struct Response *r = create_http_response(status, json);
	map_put(r->headers, "Content-Type", "application/json; charset=utf-8");
	return r;
}

static struct Response *hello_handler(struct Request *req) {
	(void)req;
	return json_response(200, "{\"message\":\"hello from API\"}");
}

static struct Response *echo_query_handler(struct Request *req) {
	// returns query params as a naive JSON object string for demo
	// WARNING: no escaping for brevity
	struct StringBuilder *sb = sb_create(0);
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
	struct Response *r = json_response(200, json);
	free(json);
	return r;
}

int main() {
	struct Server server;
	server_init(&server, "127.0.0.1", SERVER_DEFAULT_PORT);

	// Global middleware
	server_use(&server, logger_mw, NULL);

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
	router_destroy(api);
	return 0;
}
