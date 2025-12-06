#include "arena.h"
#include "json.h"
#include <log.h>
#include <map.h>
#include <server.h>
#include <stdio.h>
#include <stdlib.h>

static void json_header_mw(struct Request *req, struct Response **res,
						   bool *stop, void *user_data, Arena *arena) {
	(void)req;
	(void)stop;
	(void)user_data;
	(void)arena;
	if (*res && (*res)->headers) {
		(void)map_put((*res)->headers, "Content-Type",
					  str_duplicate("application/json; charset=utf-8"));
	}
}

struct Response *hello_handler(struct Request *request, Arena *arena) {
	(void)request;
	return create_http_response(200, "Hello, World!", arena);
}

struct Response *param_route(struct Request *request, Arena *arena) {
	char *id = (char *)map_get(request->params, "id");
	char buff[256];

	struct JsonValue *response_json = json_create_object(arena);
	(void)map_put(response_json->object_value, "id",
				  json_create_string(arena, id));

	snprintf(buff, 256, "Hello, user %s!", id ? id : "unknown");
	(void)map_put(response_json->object_value, "message",
				  json_create_string(arena, buff));

	struct Response *r =
		create_http_response(200, json_serialize(arena, response_json), arena);
	// json_free not needed - arena handles cleanup
	(void)map_put(
		r->headers, "Content-Type",
		arena_str_duplicate(arena, "application/json; charset=utf-8"));
	return r;
}

int main() {
	logger_init(LOG_LEVEL_DEBUG, "server.log");
	struct Server server;
	server_init(&server, "127.0.0.1", 8080);

	// Global JSON header middleware
	server_use(&server, json_header_mw, NULL);

	// Mount /api router and add routes
	struct Router *api = router_create();
	router_use(api, json_header_mw, NULL);
	server_mount_router(&server, "/api", api);

	// Parameterized route
	router_add(api, HTTP_GET, "/users/:id", param_route);

	// Root without router
	server_add_endpoint(&server, HTTP_GET, "/", hello_handler);

	server_start(&server); // Essentially an __no_return

	// Cleanup (this won't be reached unless server_start returns)

	server_destroy(&server);
	logger_cleanup();

	return 0;
}
