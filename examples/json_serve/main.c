#include "common.h"
#include "json.h"
#include "map.h"
#include "server.h"
#include <log.h>
#include <stdlib.h>


struct JsonValue *create_dummy_object(struct Arena *arena) {
	struct JsonValue *v = json_create_object(arena);
	if (!v)
		return NULL;
	(void)map_put(v->object_value, "message",
				  json_create_string(arena, "This is a dummy object"));
	return v;
}

static void json_header_mw(struct Request *req, struct Response **res,
						   bool *stop, void *ud, Arena *arena) {
	(void)req;
	(void)stop;
	(void)ud;
	(void)arena;
	if (*res && (*res)->headers) {
		(void)map_put((*res)->headers, "Content-Type",
					  str_duplicate("application/json; charset=utf-8"));
	}
}

struct Response *ping_handler(struct Request *request, Arena *arena) {
	(void)request;
	struct JsonValue *response_json = json_create_object(arena);

	(void)map_put(response_json->object_value, "status",
				  json_create_string(arena, "OK"));
	(void)map_put(response_json->object_value, "message",
				  json_create_string(arena, "Pong from libserver!"));

	char *response_body = json_serialize(arena, response_json);
	struct Response *r = create_http_response(200, response_body, arena);
	(void)map_put(r->headers, "Content-Type",
				  str_duplicate("application/json; charset=utf-8"));
	return r;
}

struct Response *random_number_handler(struct Request *request, Arena *arena) {
	(void)request;
	struct JsonValue *response_json = json_create_object(arena);

	int count = map_get(request->query_params, "count")
					? atoi(map_get(request->query_params, "count"))
					: 1;

	(void)map_put(response_json->object_value, "count",
				  json_create_number(arena, count));

	struct JsonValue *numbers_array = json_create_array(arena);
	numbers_array->array_value.items =
		arena_alloc(arena, count * sizeof(struct JsonValue *));

	for (int i = 0; i < count; i++) {
		int num = rand() % 100; // Random number between 0 and 99
		struct JsonValue *num_value = json_create_number(arena, num);
		numbers_array->array_value.items[i] = num_value;
		numbers_array->array_value.count++;
	}

	(void)map_put(response_json->object_value, "numbers", numbers_array);
	char *response_body = json_serialize(arena, response_json);
	struct Response *r = create_http_response(200, response_body, arena);
	return r;
}

struct Response *not_found_handler(struct Request *request, Arena *arena) {
	(void)request;
	struct JsonValue *response_json = json_create_object(arena);
	(void)map_put(response_json->object_value, "error",
				  json_create_string(arena, "Not Found"));
	char *response_body = json_serialize(arena, response_json);
	struct Response *r = create_http_response(404, response_body, arena);
	(void)map_put(r->headers, "Content-Type",
				  str_duplicate("application/json; charset=utf-8"));
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
	router_add(api, HTTP_GET, "/random", random_number_handler);

	server_mount_router(&server, "/api", api);

	server_add_endpoint(&server, HTTP_GET, "/ping", ping_handler);

	server_start(&server); // no return

	return -1;
}
