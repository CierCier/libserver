#define _GNU_SOURCE
#include "protocols/ftp.h"
#include "common.h"
#include "protocols/ftp_http.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

struct S_FtpCommand *parse_ftp_command(const char *cmd_str) {
	if (!cmd_str)
		return NULL;
	struct S_FtpCommand *cmd = malloc(sizeof(struct S_FtpCommand));
	if (!cmd)
		return NULL;
	memset(cmd, 0, sizeof(struct S_FtpCommand));
	cmd->command = FTP_CMD_UNKNOWN;

	char *copy = str_duplicate(cmd_str);
	if (!copy) {
		free(cmd);
		return NULL;
	}

	char *p = copy;
	char *token = strtok_r(p, " \r\n", &p);

	if (token) {
		// Uppercase the command
		for (int i = 0; token[i]; i++)
			token[i] = toupper(token[i]);

		if (strcmp(token, "USER") == 0)
			cmd->command = FTP_CMD_USER;
		else if (strcmp(token, "PASS") == 0)
			cmd->command = FTP_CMD_PASS;
		else if (strcmp(token, "QUIT") == 0)
			cmd->command = FTP_CMD_QUIT;
		else if (strcmp(token, "PWD") == 0)
			cmd->command = FTP_CMD_PWD;
		else if (strcmp(token, "CWD") == 0)
			cmd->command = FTP_CMD_CWD;
		else if (strcmp(token, "LIST") == 0)
			cmd->command = FTP_CMD_LIST;
		else if (strcmp(token, "RETR") == 0)
			cmd->command = FTP_CMD_RETR;
		else if (strcmp(token, "STOR") == 0)
			cmd->command = FTP_CMD_STOR;
		else if (strcmp(token, "TYPE") == 0)
			cmd->command = FTP_CMD_TYPE;
		else if (strcmp(token, "PORT") == 0)
			cmd->command = FTP_CMD_PORT;
		else if (strcmp(token, "PASV") == 0)
			cmd->command = FTP_CMD_PASV;
		else if (strcmp(token, "GET") == 0)
			cmd->command = FTP_CMD_HTTP_GET;
		else if (strcmp(token, "MKD") == 0)
			cmd->command = FTP_CMD_MKD;
		else if (strcmp(token, "RMD") == 0)
			cmd->command = FTP_CMD_RMD;
		else if (strcmp(token, "DELE") == 0)
			cmd->command = FTP_CMD_DELE;

		// Get argument
		const char *arg_start = strchr(cmd_str, ' ');
		if (arg_start) {
			while (*arg_start == ' ')
				arg_start++;
			strncpy(cmd->argument, arg_start, FTP_BUFFER_SIZE - 1);
			// Trim trailing CRLF
			// Fuck DOS ig
			char *end = cmd->argument + strlen(cmd->argument) - 1;
			while (end > cmd->argument && isspace((unsigned char)*end)) {
				*end = '\0';
				end--;
			}

			// Special handling for HTTP GET: remove " HTTP/1.1" suffix
			if (cmd->command == FTP_CMD_HTTP_GET) {
				char *http_ver = strstr(cmd->argument, " HTTP/");
				if (http_ver) {
					*http_ver = '\0';
				}
				// If path is empty or just space, default to "." or "/"
				if (strlen(cmd->argument) == 0) {
					strcpy(cmd->argument, ".");
				} else if (strcmp(cmd->argument, "/") == 0) {
					// Map root to current directory
					strcpy(cmd->argument, ".");
				} else if (cmd->argument[0] == '/') {
					// Remove leading slash for local file system access
					// (simplified) In real app, we'd map this properly
					memmove(cmd->argument, cmd->argument + 1,
							strlen(cmd->argument));
					if (strlen(cmd->argument) == 0)
						strcpy(cmd->argument, ".");
				}
			}
		}
	}
	free(copy);
	return cmd;
}

void free_ftp_command(struct S_FtpCommand *cmd) {
	if (cmd)
		free(cmd);
}

void send_ftp_response(int client_sock, const char *response) {
	if (client_sock < 0 || !response)
		return;
	char buffer[FTP_BUFFER_SIZE];
	snprintf(buffer, sizeof(buffer), "%s\r\n", response);
	write(client_sock, buffer, strlen(buffer));
}

static int open_data_connection(struct FtpContext *ctx) {
	if (ctx->data_listener_sock >= 0) {
		struct sockaddr_in client_addr;
		socklen_t len = sizeof(client_addr);
		int sock = accept(ctx->data_listener_sock,
						  (struct sockaddr *)&client_addr, &len);
		if (sock >= 0) {
			close(ctx->data_listener_sock);
			ctx->data_listener_sock = -1;
			return sock;
		}
	}
	return -1;
}

void handle_ftp_command(struct FtpContext *ctx, struct S_FtpCommand *cmd, Arena *arena) {
	if (!ctx || !cmd)
		return;

	int client_sock = ctx->control_sock;

	switch (cmd->command) {
	case FTP_CMD_USER:
		send_ftp_response(client_sock, FTP_RESP_331);
		break;
	case FTP_CMD_PASS:
		send_ftp_response(client_sock, FTP_RESP_230);
		break;
	case FTP_CMD_QUIT:
		send_ftp_response(client_sock, FTP_RESP_221);
		break;
	case FTP_CMD_PWD: {
		char resp[FTP_BUFFER_SIZE];
		// Return absolute path for now, or strip root if we tracked it
		snprintf(resp, sizeof(resp), "257 \"%s\"", ctx->current_dir);
		send_ftp_response(client_sock, resp);
		break;
	}
	case FTP_CMD_CWD: {
		char new_path[PATH_MAX];
		if (cmd->argument[0] == '/') {
			snprintf(new_path, sizeof(new_path), "%s",
					 cmd->argument); // Treat as absolute
		} else {
			snprintf(new_path, sizeof(new_path), "%s/%s", ctx->current_dir,
					 cmd->argument);
		}

		char resolved[PATH_MAX];
		if (realpath(new_path, resolved) && access(resolved, F_OK) == 0) {
			// Security check: ensure we are still within root_dir
			size_t root_len = strlen(ctx->root_dir);
			if (strncmp(resolved, ctx->root_dir, root_len) != 0 ||
				(resolved[root_len] != '\0' && resolved[root_len] != '/')) {
				send_ftp_response(client_sock, FTP_RESP_550);
				break;
			}

			struct stat st;
			stat(resolved, &st);
			if (S_ISDIR(st.st_mode)) {
				strncpy(ctx->current_dir, resolved,
						sizeof(ctx->current_dir) - 1);
				send_ftp_response(client_sock, FTP_RESP_200);
			} else {
				send_ftp_response(client_sock, FTP_RESP_550);
			}
		} else {
			send_ftp_response(client_sock, FTP_RESP_550);
		}
		break;
	}
	case FTP_CMD_TYPE:
		send_ftp_response(client_sock, FTP_RESP_200);
		break;
	case FTP_CMD_PORT:
		send_ftp_response(client_sock,
						  "502 Command not implemented (use PASV).");
		break;
	case FTP_CMD_PASV: {
		// Create ephemeral listener
		int listener = socket(AF_INET, SOCK_STREAM, 0);
		if (listener < 0) {
			send_ftp_response(client_sock, FTP_RESP_425);
			return;
		}
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = 0; // Ephemeral

		if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
			listen(listener, 1) < 0) {
			close(listener);
			send_ftp_response(client_sock, FTP_RESP_425);
			return;
		}

		socklen_t len = sizeof(addr);
		getsockname(listener, (struct sockaddr *)&addr, &len);
		int port = ntohs(addr.sin_port);

		ctx->data_listener_sock = listener;

		// Get local IP (hacky, assume 127.0.0.1 for now or use getsockname on
		// control sock) For browser compatibility, we need the IP the client
		// connected to. Here we just send 127,0,0,1
		char resp[FTP_BUFFER_SIZE];
		snprintf(resp, sizeof(resp), FTP_RESP_227, 127, 0, 0, 1, port / 256,
				 port % 256);
		send_ftp_response(client_sock, resp);
		break;
	}
	case FTP_CMD_LIST: {
		int data_sock = open_data_connection(ctx);
		if (data_sock < 0) {
			send_ftp_response(client_sock, FTP_RESP_425);
			return;
		}
		send_ftp_response(client_sock, FTP_RESP_150);

		DIR *d = opendir(ctx->current_dir);
		if (d) {
			struct dirent *dir;
			char line[FTP_BUFFER_SIZE];
			while ((dir = readdir(d)) != NULL) {
				char full_path[PATH_MAX];
				snprintf(full_path, sizeof(full_path), "%s/%s",
						 ctx->current_dir, dir->d_name);

				struct stat st;
				if (stat(full_path, &st) == 0) {
					char date[64];
					strftime(date, sizeof(date), "%b %d %H:%M",
							 localtime(&st.st_mtime));

					snprintf(line, sizeof(line), "%s 1 ftp ftp %ld %s %s\r\n",
							 (S_ISDIR(st.st_mode)) ? "drwxr-xr-x"
												   : "-rw-r--r--",
							 st.st_size, date, dir->d_name);
					write(data_sock, line, strlen(line));
				}
			}
			closedir(d);
		}
		close(data_sock);
		send_ftp_response(client_sock, FTP_RESP_226);
		break;
	}
	case FTP_CMD_RETR: {
		int data_sock = open_data_connection(ctx);
		if (data_sock < 0) {
			send_ftp_response(client_sock, FTP_RESP_425);
			return;
		}

		char full_path[PATH_MAX];
		snprintf(full_path, sizeof(full_path), "%s/%s", ctx->current_dir,
				 cmd->argument);

		FILE *f = fopen(full_path, "rb");
		if (f) {
			send_ftp_response(client_sock, FTP_RESP_150);
			char buf[4096];
			size_t n;
			while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
				write(data_sock, buf, n);
			}
			fclose(f);
			close(data_sock);
			send_ftp_response(client_sock, FTP_RESP_226);
		} else {
			close(data_sock);
			send_ftp_response(client_sock, FTP_RESP_550);
		}
		break;
	}
	case FTP_CMD_STOR: {
		int data_sock = open_data_connection(ctx);
		if (data_sock < 0) {
			send_ftp_response(client_sock, FTP_RESP_425);
			return;
		}

		// Security check
		if (strstr(cmd->argument, "..")) {
			close(data_sock);
			send_ftp_response(client_sock, FTP_RESP_550);
			return;
		}

		char full_path[PATH_MAX];
		snprintf(full_path, sizeof(full_path), "%s/%s", ctx->current_dir,
				 cmd->argument);

		FILE *f = fopen(full_path, "wb");
		if (f) {
			send_ftp_response(client_sock, FTP_RESP_150);
			char buf[4096];
			size_t n;
			while ((n = read(data_sock, buf, sizeof(buf))) > 0) {
				fwrite(buf, 1, n, f);
			}
			fclose(f);
			close(data_sock);
			send_ftp_response(client_sock, FTP_RESP_226);
		} else {
			close(data_sock);
			send_ftp_response(client_sock, FTP_RESP_550);
		}
		break;
	}
	case FTP_CMD_MKD: {
		// Security check
		if (strstr(cmd->argument, "..")) {
			send_ftp_response(client_sock, FTP_RESP_550);
			break;
		}
		char full_path[PATH_MAX];
		snprintf(full_path, sizeof(full_path), "%s/%s", ctx->current_dir,
				 cmd->argument);
		if (mkdir(full_path, 0755) == 0) {
			send_ftp_response(client_sock, "257 Directory created.");
		} else {
			send_ftp_response(client_sock, FTP_RESP_550);
		}
		break;
	}
	case FTP_CMD_RMD: {
		// Security check
		if (strstr(cmd->argument, "..")) {
			send_ftp_response(client_sock, FTP_RESP_550);
			break;
		}
		char full_path[PATH_MAX];
		snprintf(full_path, sizeof(full_path), "%s/%s", ctx->current_dir,
				 cmd->argument);
		if (rmdir(full_path) == 0) {
			send_ftp_response(client_sock, FTP_RESP_250);
		} else {
			send_ftp_response(client_sock, FTP_RESP_550);
		}
		break;
	}
	case FTP_CMD_DELE: {
		// Security check
		if (strstr(cmd->argument, "..")) {
			send_ftp_response(client_sock, FTP_RESP_550);
			break;
		}
		char full_path[PATH_MAX];
		snprintf(full_path, sizeof(full_path), "%s/%s", ctx->current_dir,
				 cmd->argument);
		if (unlink(full_path) == 0) {
			send_ftp_response(client_sock, FTP_RESP_250);
		} else {
			send_ftp_response(client_sock, FTP_RESP_550);
		}
		break;
	} break;
	case FTP_CMD_HTTP_GET: {
		// Serve HTTP response
		// Use the shared FTP HTTP handler
		struct Request req = {0};
		req.method = HTTP_GET;
		req.path = cmd->argument;

		struct Response *res = ftp_handle_http_request_with_options(
			&req, ctx->current_dir, ctx->css_path, arena);
		if (res) {
			send_http_response(client_sock, res);
		} else {
			// Fallback error
			const char *err = "HTTP/1.1 500 Internal Server "
							  "Error\r\nContent-Length: 0\r\n\r\n";
			write(client_sock, err, strlen(err));
		}
		break;
	}
	default:
		send_ftp_response(client_sock, FTP_RESP_500);
		break;
	}
}

const char *ftp_command_to_string(E_FtpCommand cmd) {
	switch (cmd) {
	case FTP_CMD_USER:
		return "USER";
	case FTP_CMD_PASS:
		return "PASS";
	case FTP_CMD_QUIT:
		return "QUIT";
	case FTP_CMD_PWD:
		return "PWD";
	case FTP_CMD_CWD:
		return "CWD";
	case FTP_CMD_LIST:
		return "LIST";
	case FTP_CMD_RETR:
		return "RETR";
	case FTP_CMD_STOR:
		return "STOR";
	case FTP_CMD_TYPE:
		return "TYPE";
	case FTP_CMD_PORT:
		return "PORT";
	case FTP_CMD_PASV:
		return "PASV";
	default:
		return "UNKNOWN";
	}
}
