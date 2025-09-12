#include "common.h"
#include "json.h"
#include "map.h"
#include "server.h"
#include <log.h>
#include <stdio.h>

struct Response *ping_handler(struct Request *request) {
	(void)request;
	struct JsonValue *response_json = json_create_object();

	map_put(response_json->object_value, "status", json_create_string("OK"));
	map_put(response_json->object_value, "message",
			json_create_string("Pong from libserver!"));

	char *response_body = json_serialize(response_json);
	json_free(response_json);
	return create_http_response(200, response_body);
}

struct Response *not_found_handler(struct Request *request) {
	(void)request;

	static int initialized = 0;
	static struct JsonValue *response_json = NULL;
	if (!initialized) {
		response_json = json_create_object();
		map_put(response_json->object_value, "error",
				json_create_string("Not Found"));
		initialized = 1;
	}

	char *response_body = json_serialize(response_json);
	json_free(response_json);
	return create_http_response(404, response_body);
}

int main(int argc, char **argv) {
	logger_init(LOG_LEVEL_DEBUG, "server.log");
	struct Server server;
	server_init(&server, "127.0.0.1", 8080);

	struct EndPoint *ping_endpoint =
		endpoint_create(HTTP_GET, "/ping", ping_handler);

	server_add_endpoint(&server, ping_endpoint);
	server_start(&server);

	return -1;
}