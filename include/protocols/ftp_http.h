#pragma once

#include "common.h"

// Initialize the FTP driver configuration
void ftp_driver_init(const char *root_dir, const char *css_path);

// Request handler for FTP over HTTP
struct Response *ftp_http_handler(struct Request *req);

// Request handler with explicit options (for internal use or advanced cases)
struct Response *ftp_handle_http_request_with_options(struct Request *req, const char *root_dir, const char *css_path);
