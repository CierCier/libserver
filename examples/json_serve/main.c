#include "common.h"
#include "json.h"
#include "map.h"
#include "server.h"
#include <log.h>
#include <stdlib.h>

static void json_header_mw(struct Request *req, struct Response **res,
						   bool *stop, void *ud) {
	(void)req;
	(void)stop;
	(void)ud;
	if (*res && (*res)->headers) {
		map_put((*res)->headers, "Content-Type",
				"application/json; charset=utf-8");
	}
}

struct Response *ping_handler(struct Request *request) {
	(void)request;
	struct JsonValue *response_json = json_create_object();

	map_put(response_json->object_value, "status", json_create_string("OK"));
	map_put(response_json->object_value, "message",
			json_create_string("Pong from libserver!"));

	char *response_body = json_serialize(response_json);
	json_free(response_json);
	struct Response *r = create_http_response(200, response_body);
	map_put(r->headers, "Content-Type", "application/json; charset=utf-8");
	free(response_body);
	return r;
}

struct Response *not_found_handler(struct Request *request) {
	(void)request;
	struct JsonValue *response_json = json_create_object();
	map_put(response_json->object_value, "error",
			json_create_string("Not Found"));
	char *response_body = json_serialize(response_json);
	json_free(response_json);
	struct Response *r = create_http_response(404, response_body);
	map_put(r->headers, "Content-Type", "application/json; charset=utf-8");
	free(response_body);
	return r;
}

int main(int argc, char **argv) {
	logger_init(LOG_LEVEL_DEBUG, "server.log");
	struct Server server;
	server_init(&server, "127.0.0.1", 8080);

	// Set custom 404
	static struct EndPoint nep = {HTTP_GET, "/404", not_found_handler};
	server.not_found_endpoint = &nep;

	server_use(&server, json_header_mw, NULL);

	// Use a router for API endpoints
	struct Router *api = router_create();
	router_add(api, HTTP_GET, "/ping", ping_handler);
	server_mount_router(&server, "/api", api);

	// Optional: keep /ping at root as well
	server_add_endpoint(&server, HTTP_GET, "/ping", ping_handler);

	server_start(&server); // no return

	return -1;
}
