#include "protocols/ftp.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <poll.h>

#define PORT 2121

void *client_handler(void *arg) {
	int client_sock = *(int *)arg;
	free(arg);

	struct FtpContext ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.control_sock = client_sock;
	ctx.data_listener_sock = -1;
	ctx.data_sock = -1;
	if (getcwd(ctx.root_dir, sizeof(ctx.root_dir)) == NULL) {
		strcpy(ctx.root_dir, ".");
	}
	strcpy(ctx.current_dir, ctx.root_dir);
	// Set path to style.css (assuming running from project root or build dir)
	// Since we run from build/examples/, and style.css is in examples/ftp_server/
	// We need to point to the source location or copy it.
	// For now, let's assume the user runs from project root as per instructions: ./build/examples/example_ftp_server
	// So path is examples/ftp_server/style.css
	strcpy(ctx.css_path, "examples/ftp_server/style.css");

	// Protocol sniffing: Wait briefly for data. 
	// If client sends "GET", it's HTTP (don't send greeting).
	// If timeout, it's FTP (send greeting).
	struct pollfd pfd;
	pfd.fd = client_sock;
	pfd.events = POLLIN;
	
	int ret = poll(&pfd, 1, 200); // 200ms wait
	bool is_http = false;
	
	if (ret > 0 && (pfd.revents & POLLIN)) {
		char peek_buf[16];
		ssize_t n = recv(client_sock, peek_buf, sizeof(peek_buf) - 1, MSG_PEEK);
		if (n > 0) {
			peek_buf[n] = '\0';
			if (strncmp(peek_buf, "GET ", 4) == 0) {
				is_http = true;
			}
		}
	}

	if (!is_http) {
		send_ftp_response(client_sock, FTP_RESP_220);
	}

	char buffer[FTP_BUFFER_SIZE];
	while (1) {
		memset(buffer, 0, sizeof(buffer));
		ssize_t bytes_read = read(client_sock, buffer, sizeof(buffer) - 1);
		if (bytes_read <= 0) {
			break;
		}

		struct S_FtpCommand *cmd = parse_ftp_command(buffer);
		if (cmd) {
			printf("Received command: %s %s\n",
				   ftp_command_to_string(cmd->command), cmd->argument);
			handle_ftp_command(&ctx, cmd);
			bool quit = (cmd->command == FTP_CMD_QUIT || cmd->command == FTP_CMD_HTTP_GET);
			free_ftp_command(cmd);
			if (quit)
				break;
		} else {
			send_ftp_response(client_sock, FTP_RESP_500);
		}
	}

	if (ctx.data_listener_sock >= 0)
		close(ctx.data_listener_sock);
	if (ctx.data_sock >= 0)
		close(ctx.data_sock);

	close(client_sock);
	printf("Client disconnected\n");
	return NULL;
}

int main() {
	int server_sock, client_sock;
	struct sockaddr_in server_addr, client_addr;
	socklen_t addr_len = sizeof(client_addr);

	server_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (server_sock < 0) {
		perror("socket");
		exit(1);
	}

	int opt = 1;
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(PORT);

	if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
		0) {
		perror("bind");
		exit(1);
	}

	if (listen(server_sock, 5) < 0) {
		perror("listen");
		exit(1);
	}

	printf("FTP Server listening on port %d\n", PORT);

	while (1) {
		client_sock =
			accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
		if (client_sock < 0) {
			perror("accept");
			continue;
		}

		printf("Client connected from %s:%d\n", inet_ntoa(client_addr.sin_addr),
			   ntohs(client_addr.sin_port));

		int *arg = malloc(sizeof(int));
		*arg = client_sock;

		pthread_t tid;
		pthread_create(&tid, NULL, client_handler, arg);
		pthread_detach(tid);
	}

	close(server_sock);
	return 0;
}
