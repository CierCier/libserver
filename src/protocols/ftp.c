#include "common.h"
#include "protocols/ftp.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
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

		// Get argument
		const char *arg_start = strchr(cmd_str, ' ');
		if (arg_start) {
			while (*arg_start == ' ')
				arg_start++;
			strncpy(cmd->argument, arg_start, FTP_BUFFER_SIZE - 1);
			// Trim trailing CRLF
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
                    // Remove leading slash for local file system access (simplified)
                    // In real app, we'd map this properly
                    memmove(cmd->argument, cmd->argument + 1, strlen(cmd->argument));
                    if (strlen(cmd->argument) == 0) strcpy(cmd->argument, ".");
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
		int sock = accept(ctx->data_listener_sock, (struct sockaddr *)&client_addr, &len);
		if (sock >= 0) {
			close(ctx->data_listener_sock);
			ctx->data_listener_sock = -1;
			return sock;
		}
	}
	return -1;
}

void handle_ftp_command(struct FtpContext *ctx, struct S_FtpCommand *cmd) {
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
		snprintf(resp, sizeof(resp), "257 \"%s\"", ctx->current_dir[0] ? ctx->current_dir : "/");
		send_ftp_response(client_sock, resp);
		break;
	}
	case FTP_CMD_CWD:
		// Simplified CWD: just update current_dir if it exists
		// In a real server, we would check if the directory exists
		if (cmd->argument[0] == '/') {
			strncpy(ctx->current_dir, cmd->argument, sizeof(ctx->current_dir) - 1);
		} else {
			// Handle relative path (simplified)
			if (strcmp(ctx->current_dir, "/") != 0)
				strncat(ctx->current_dir, "/", sizeof(ctx->current_dir) - strlen(ctx->current_dir) - 1);
			strncat(ctx->current_dir, cmd->argument, sizeof(ctx->current_dir) - strlen(ctx->current_dir) - 1);
		}
		send_ftp_response(client_sock, FTP_RESP_200);
		break;
	case FTP_CMD_TYPE:
		send_ftp_response(client_sock, FTP_RESP_200);
		break;
	case FTP_CMD_PORT:
		send_ftp_response(client_sock, "502 Command not implemented (use PASV).");
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

		if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(listener, 1) < 0) {
			close(listener);
			send_ftp_response(client_sock, FTP_RESP_425);
			return;
		}

		socklen_t len = sizeof(addr);
		getsockname(listener, (struct sockaddr *)&addr, &len);
		int port = ntohs(addr.sin_port);
		
		ctx->data_listener_sock = listener;

		// Get local IP (hacky, assume 127.0.0.1 for now or use getsockname on control sock)
		// For browser compatibility, we need the IP the client connected to.
		// Here we just send 127,0,0,1
		char resp[FTP_BUFFER_SIZE];
		snprintf(resp, sizeof(resp), FTP_RESP_227, 127, 0, 0, 1, port / 256, port % 256);
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

		// List current directory
		// For security, we only list the current working directory of the process
		// In a real server, we would chroot or sandbox
		DIR *d = opendir(".");
		if (d) {
			struct dirent *dir;
			char line[FTP_BUFFER_SIZE];
			while ((dir = readdir(d)) != NULL) {
				// Simplified LIST format: -rw-r--r-- 1 owner group size date name
				// We just send name for now to be simple, browsers might need more
				// Let's try to fake a unix listing
				struct stat st;
				stat(dir->d_name, &st);
				char date[64];
				strftime(date, sizeof(date), "%b %d %H:%M", localtime(&st.st_mtime));
				
				snprintf(line, sizeof(line), "%s 1 ftp ftp %ld %s %s\r\n", 
					(S_ISDIR(st.st_mode)) ? "drwxr-xr-x" : "-rw-r--r--",
					st.st_size, date, dir->d_name);
				write(data_sock, line, strlen(line));
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
		
		// Security check: prevent directory traversal
		if (strstr(cmd->argument, "..")) {
			close(data_sock);
			send_ftp_response(client_sock, FTP_RESP_550);
			return;
		}

		FILE *f = fopen(cmd->argument, "rb");
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
	case FTP_CMD_STOR:
		send_ftp_response(client_sock, "502 Command not implemented.");
		break;
	case FTP_CMD_HTTP_GET: {
		// Serve HTTP response
		// Check if it's a directory or file
			// Special handling for style.css
			if (strcmp(cmd->argument, "/style.css") == 0 || strcmp(cmd->argument, "style.css") == 0) {
				const char *css_file = (ctx->css_path[0] != '\0') ? ctx->css_path : "style.css";
				FILE *f = fopen(css_file, "rb");
				if (f) {
					fseek(f, 0, SEEK_END);
					long fsize = ftell(f);
					fseek(f, 0, SEEK_SET);
					
					char header[512];
					snprintf(header, sizeof(header), 
						"HTTP/1.1 200 OK\r\n"
						"Content-Type: text/css\r\n"
						"Content-Length: %ld\r\n"
						"Connection: close\r\n"
						"\r\n", fsize);
					write(client_sock, header, strlen(header));
					
					char buf[4096];
					size_t n;
					while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
						write(client_sock, buf, n);
					}
					fclose(f);
				} else {
					const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
					write(client_sock, not_found, strlen(not_found));
				}
				break;
			}

			struct stat st;
			if (stat(cmd->argument, &st) == 0) {
				if (S_ISDIR(st.st_mode)) {
					// Directory listing
					char body[65536]; // Increased buffer size
					snprintf(body, sizeof(body), 
						"<html><head>"
						"<link rel=\"stylesheet\" href=\"/style.css\">"
						"</head><body>"
						"<h1>Directory Listing of %s</h1>"
						"<table><tr><th>Name</th><th>Size</th><th>Last Modified</th></tr>", 
						cmd->argument);
				
				DIR *d = opendir(cmd->argument);
				if (d) {
					struct dirent *dir;
					while ((dir = readdir(d)) != NULL) {
						char full_path[FTP_BUFFER_SIZE * 2];
						if (strcmp(cmd->argument, ".") == 0)
							snprintf(full_path, sizeof(full_path), "%s", dir->d_name);
						else
							snprintf(full_path, sizeof(full_path), "%s/%s", cmd->argument, dir->d_name);

						struct stat st_file;
						char size_str[32] = "-";
						char date_str[64] = "-";
						
						if (stat(full_path, &st_file) == 0) {
							if (!S_ISDIR(st_file.st_mode)) {
								snprintf(size_str, sizeof(size_str), "%ld", st_file.st_size);
							}
							strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", localtime(&st_file.st_mtime));
						}

						char line[1024];
						char href[1024];
						
						if (strcmp(cmd->argument, "/") == 0 || strcmp(cmd->argument, ".") == 0)
							snprintf(href, sizeof(href), "%s", dir->d_name);
						else
							snprintf(href, sizeof(href), "%s/%s", cmd->argument, dir->d_name);

						snprintf(line, sizeof(line), 
							"<tr><td><a href=\"%s\">%s</a></td><td>%s</td><td>%s</td></tr>", 
							href, dir->d_name, size_str, date_str);
							
						if (strlen(body) + strlen(line) < sizeof(body) - 100)
							strncat(body, line, sizeof(body) - strlen(body) - 1);
					}
					closedir(d);
				}
				strncat(body, "</table></body></html>", sizeof(body) - strlen(body) - 1);
				
				char response[20000];
				snprintf(response, sizeof(response), 
					"HTTP/1.1 200 OK\r\n"
					"Content-Type: text/html\r\n"
					"Content-Length: %zu\r\n"
					"Connection: close\r\n"
					"\r\n"
					"%s", strlen(body), body);
				write(client_sock, response, strlen(response));
			} else {
				// File download
				FILE *f = fopen(cmd->argument, "rb");
				if (f) {
					fseek(f, 0, SEEK_END);
					long fsize = ftell(f);
					fseek(f, 0, SEEK_SET);
					
					char header[512];
					snprintf(header, sizeof(header), 
						"HTTP/1.1 200 OK\r\n"
						"Content-Type: application/octet-stream\r\n"
						"Content-Length: %ld\r\n"
						"Connection: close\r\n"
						"\r\n", fsize);
					write(client_sock, header, strlen(header));
					
					char buf[4096];
					size_t n;
					while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
						write(client_sock, buf, n);
					}
					fclose(f);
				} else {
					const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
					write(client_sock, not_found, strlen(not_found));
				}
			}
		} else {
			const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
			write(client_sock, not_found, strlen(not_found));
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
