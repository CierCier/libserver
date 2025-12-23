#ifndef SERVER_HTTP2_H
#define SERVER_HTTP2_H

#include "server.h"
#include <openssl/ssl.h>

/*
 * Handles an HTTP/2 session on the given socket (and SSL context).
 * This function blocks until the session ends.
 */
void handle_http2_session(struct Server *server, int sock, SSL *ssl);

#endif // SERVER_HTTP2_H
