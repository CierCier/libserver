#include <log.h>
#include <map.h>
#include <server.h>
#include <stdio.h>

struct Response *hello_handler(struct Request *request) {
	(void)request;
	return create_http_response(200, "Hello, World from libserver!");
}

struct Response *status_handler(struct Request *request) {
	(void)request;
	return create_http_response(
		200, "{\"status\": \"OK\", \"message\": \"Server is running\"}");
}

struct Response *echo_handler(struct Request *request) {
	if (!request || !request->query_params) {
		return create_http_response(400, "Invalid request");
	}

	char *message = (char *)map_get(request->query_params, "message");
	char *name = (char *)map_get(request->query_params, "name");

	char response_body[1024];
	if (message && name) {
		snprintf(response_body, sizeof(response_body),
				 "{\"echo\": \"%s\", \"name\": \"%s\", \"full_message\": "
				 "\"Hello %s, you said: %s\"}",
				 message, name, name, message);
	} else if (message) {
		snprintf(response_body, sizeof(response_body),
				 "{\"echo\": \"%s\", \"message\": \"You said: %s\"}", message,
				 message);
	} else if (name) {
		snprintf(response_body, sizeof(response_body),
				 "{\"name\": \"%s\", \"message\": \"Hello %s!\"}", name, name);
	} else {
		snprintf(response_body, sizeof(response_body),
				 "{\"message\": \"No query parameters provided. Try: "
				 "/api/echo?message=hello&name=world\"}");
	}

	return create_http_response(200, response_body);
}

int main() {
	logger_init(LOG_LEVEL_DEBUG, "server.log");

	printf("Starting basic libserver example...\n");

	struct Server server;
	server_init(&server, "127.0.0.1", 8080);

	struct EndPoint *hello_endpoint =
		endpoint_create(HTTP_GET, "/", hello_handler);
	struct EndPoint *status_endpoint =
		endpoint_create(HTTP_GET, "/api/status", status_handler);
	struct EndPoint *echo_endpoint =
		endpoint_create(HTTP_GET, "/api/echo", echo_handler);

	server_add_endpoint(&server, hello_endpoint);
	server_add_endpoint(&server, status_endpoint);
	server_add_endpoint(&server, echo_endpoint);

	printf("Server configured with endpoints:\n");
	printf("  GET / - Hello World\n");
	printf("  GET /api/status - Status check\n");
	printf("  GET /api/echo - Echo with query parameters\n");
	printf("    Example: /api/echo?message=hello&name=world\n");
	printf("\nStarting server on http://127.0.0.1:8080\n");
	printf("Press Ctrl+C to stop the server\n\n");

	server_start(&server); // Essentially an __no_return

	// Cleanup (this won't be reached unless server_start returns)
	// --- IGNORE ---

	server_destroy(&server);
	logger_cleanup();

	return 0;
}
