#include "log.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct Logger {
	LogLevel level; // Current logging level (Only logs messages at or below
					// this level)
	FILE *log_file;
	pthread_mutex_t lock;
} logger;

const char *log_level_to_string(LogLevel level) {
	switch (level) {
	case LOG_LEVEL_ERROR:
		return "ERROR";
	case LOG_LEVEL_WARNING:
		return "WARNING";
	case LOG_LEVEL_INFO:
		return "INFO";
	case LOG_LEVEL_DEBUG:
		return "DEBUG";
	default:
		return "UNKNOWN";
	}
}

void log_common(LogLevel level, const char *message) {
	if (logger.level >= level) {
		pthread_mutex_lock(&logger.lock);
		time_t now = time(NULL);
		char time_str[64];
		strftime(time_str, sizeof(time_str), TIME_FMT, localtime(&now));
		time_str[strlen(time_str) - 1] = '\0'; // Remove newline

		char buffer[LOG_MAX_LINE_LENGTH];
		snprintf(buffer, sizeof(buffer), "[%s] [%s] %s", time_str,
				 log_level_to_string(level), message);

		fprintf(logger.log_file, "%s\n", buffer);
		fprintf(stderr, "%s\n", buffer);

		fflush(logger.log_file);
		pthread_mutex_unlock(&logger.lock);
	}
}

void app_log(LogLevel level, const char *format, ...) {
	if (level > logger.level)
		return;

	char message[LOG_MAX_LINE_LENGTH];
	va_list args;
	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);
	log_common(level, message);
}

void logger_init(LogLevel level, const char *file_path) {
	logger.level = level;
	logger.log_file = fopen(file_path, "a");
	if (!logger.log_file) {
		fprintf(stderr, "Failed to open log file: %s\n", file_path);
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(&logger.lock, NULL);
	app_log(LOG_LEVEL_INFO, "Logger started");
}

void logger_cleanup(void) {
	if (logger.log_file && logger.log_file != stdout &&
		logger.log_file != stderr) {
		fclose(logger.log_file);
		logger.log_file = NULL;
	}
	pthread_mutex_destroy(&logger.lock);
}