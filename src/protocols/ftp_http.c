#include "protocols/ftp_http.h"
#include "stringbuilder.h"
#include <ctype.h>
#include <dirent.h>
#include <map.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char g_root_dir[1024] = ".";
static char g_css_path[1024] = "";

void ftp_driver_init(const char *root_dir, const char *css_path) {
	if (root_dir)
		strncpy(g_root_dir, root_dir, sizeof(g_root_dir) - 1);
	else
		strcpy(g_root_dir, ".");

	if (css_path)
		strncpy(g_css_path, css_path, sizeof(g_css_path) - 1);
	else
		strcpy(g_css_path, "style.css");
}

static void url_decode(char *dst, const char *src) {
	char a, b;
	while (*src) {
		if ((*src == '%') && ((a = src[1]) && (b = src[2])) &&
			(isxdigit(a) && isxdigit(b))) {
			if (a >= 'a')
				a -= 'a' - 'A';
			if (a >= 'A')
				a -= ('A' - 10);
			else
				a -= '0';
			if (b >= 'a')
				b -= 'a' - 'A';
			if (b >= 'A')
				b -= ('A' - 10);
			else
				b -= '0';
			*dst++ = 16 * a + b;
			src += 3;
		} else if (*src == '+') {
			*dst++ = ' ';
			src++;
		} else {
			*dst++ = *src++;
		}
	}
	*dst++ = '\0';
}

#include <ctype.h>

struct Response *ftp_handle_http_request_with_options(struct Request *req,
													  const char *root_dir,
													  const char *css_path,
													  Arena *arena) {
	if (req->method != HTTP_GET) {
		return create_http_response(405, "Method Not Allowed", arena);
	}

	char decoded_path[1024];
	url_decode(decoded_path, req->path);

	// Prevent directory traversal
	if (strstr(decoded_path, "..")) {
		return create_http_response(403, "Forbidden", arena);
	}

	// Handle style.css
	if (ends_with(decoded_path, "/style.css") ||
		strcmp(decoded_path, "style.css") == 0) {
		const char *actual_css_path =
			(css_path && css_path[0] != '\0') ? css_path : "style.css";
		FILE *f = fopen(actual_css_path, "rb");
		if (!f) {
			return create_http_response(404, "Not Found", arena);
		}
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		char *css_content = arena_alloc(arena, fsize + 1);
		if (!css_content) {
			fclose(f);
			return create_http_response(500, "Internal Server Error", arena);
		}
		fread(css_content, 1, fsize, f);
		css_content[fsize] = '\0';
		fclose(f);

		struct Response *res = create_http_response(200, css_content, arena);
		(void)map_put(res->headers, "Content-Type", str_duplicate("text/css"));
		return res;
	}

	// Construct full path
	char full_path[2048];
	const char *base_dir = (root_dir && root_dir[0] != '\0') ? root_dir : ".";

	// Remove leading slash from request path for concatenation
	const char *rel_path = decoded_path;
	if (rel_path[0] == '/')
		rel_path++;

	if (strcmp(base_dir, ".") == 0) {
		snprintf(full_path, sizeof(full_path), "%s",
				 rel_path[0] ? rel_path : ".");
	} else {
		snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, rel_path);
	}

	struct stat st;
	if (stat(full_path, &st) != 0) {
		return create_http_response(404, "Not Found", arena);
	}

	if (S_ISDIR(st.st_mode)) {
		StringBuilder *sb = sb_create(arena, 4096);

		char temp[1024];
		snprintf(
			temp, sizeof(temp),
			"<html><head>"
			"<link rel=\"stylesheet\" href=\"/style.css\">"
			"</head><body>"
			"<h1>Directory Listing of %s</h1>"
			"<table><tr><th>Name</th><th>Size</th><th>Last Modified</th></tr>",
			decoded_path);
		sb_append(sb, temp);

		DIR *d = opendir(full_path);
		if (d) {
			struct dirent *dir;
			while ((dir = readdir(d)) != NULL) {
				char entry_path[2048];
				snprintf(entry_path, sizeof(entry_path), "%s/%s", full_path,
						 dir->d_name);

				struct stat st_file;
				char size_str[32] = "-";
				char date_str[64] = "-";

				if (stat(entry_path, &st_file) == 0) {
					if (!S_ISDIR(st_file.st_mode)) {
						snprintf(size_str, sizeof(size_str), "%ld",
								 st_file.st_size);
					}
					strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S",
							 localtime(&st_file.st_mtime));
				}

				char href[1024];
				if (strcmp(decoded_path, "/") == 0)
					snprintf(href, sizeof(href), "%s", dir->d_name);
				else
					snprintf(href, sizeof(href), "%s/%s", decoded_path,
							 dir->d_name);

				char line[2048];
				snprintf(line, sizeof(line),
						 "<tr><td><a "
						 "href=\"%s\">%s</a></td><td>%s</td><td>%s</td></tr>",
						 href, dir->d_name, size_str, date_str);

				sb_append(sb, line);
			}
			closedir(d);
		}
		sb_append(sb, "</table></body></html>");

		char *html = sb_to_string(sb);
		sb_destroy(sb);

		struct Response *res = create_http_response(200, html, arena);
		(void)map_put(res->headers, "Content-Type", str_duplicate("text/html"));
		return res;
	} else {
		// Serve file
		FILE *f = fopen(full_path, "rb");
		if (!f) {
			return create_http_response(404, "Not Found", arena);
		}
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		char *content = arena_alloc(arena, fsize + 1);
		if (!content) {
			fclose(f);
			return create_http_response(500, "Internal Server Error", arena);
		}
		fread(content, 1, fsize, f);
		content[fsize] = '\0';
		fclose(f);

		struct Response *res = create_http_response(200, content, arena);
		(void)map_put(res->headers, "Content-Type",
					  str_duplicate("application/octet-stream"));
		return res;
	}
}

struct Response *ftp_http_handler(struct Request *req, Arena *arena) {
	return ftp_handle_http_request_with_options(req, g_root_dir, g_css_path,
												arena);
}
