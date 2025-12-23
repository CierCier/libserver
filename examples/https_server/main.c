#include "server.h"
#include <stdio.h>

struct Response *handle_root(struct Request *request, Arena *arena) {
	return create_http_response(200, "Hello, secure world!\n", arena);
}

int main() {
	struct Server server;
	server_init(&server, "0.0.0.0", 8443);

	// Enable HTTPS
	server_enable_https(&server, "certs/cert.pem", "certs/key.pem");

	server_add_endpoint(&server, HTTP_GET, "/", handle_root);

	server_start(&server);
	server_destroy(&server);
	return 0;
}
