#pragma once

// Basic FTP protocol definitions and utilities

#include <stdbool.h>
#include <stddef.h>

#define FTP_DEFAULT_PORT 21
#define FTP_BUFFER_SIZE 1024

// FTP command definitions
typedef enum {
	FTP_CMD_USER,
	FTP_CMD_PASS,
	FTP_CMD_QUIT,
	FTP_CMD_PWD,
	FTP_CMD_CWD,
	FTP_CMD_LIST,
	FTP_CMD_RETR,
	FTP_CMD_STOR,
	FTP_CMD_TYPE,
	FTP_CMD_PORT,
	FTP_CMD_PASV,
	FTP_CMD_UNKNOWN
} E_FtpCommand;

// FTP response codes
#define FTP_RESP_150 "150 File status okay; about to open data connection."
#define FTP_RESP_200 "200 Command okay."
#define FTP_RESP_220 "220 Service ready for new user."
#define FTP_RESP_221 "221 Service closing control connection."
#define FTP_RESP_230 "230 User logged in, proceed."

#define FTP_RESP_331 "331 User name okay, need password."
#define FTP_RESP_425 "425 Can't open data connection."
#define FTP_RESP_426 "426 Connection closed; transfer aborted."
#define FTP_RESP_450 "450 Requested file action not taken."
#define FTP_RESP_500 "500 Syntax error, command unrecognized."
#define FTP_RESP_530 "530 Not logged in."
#define FTP_RESP_550 "550 Requested action not taken."

struct S_FtpCommand {
	E_FtpCommand command;
	char argument[FTP_BUFFER_SIZE];
};

struct S_FtpCommand *parse_ftp_command(const char *cmd_str);

const char *ftp_command_to_string(E_FtpCommand cmd);

void free_ftp_command(struct S_FtpCommand *cmd);
void handle_ftp_command(int client_sock, struct S_FtpCommand *cmd);
void send_ftp_response(int client_sock, const char *response);