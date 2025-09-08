#pragma once

#define LOG_MAX_LINE_LENGTH 1024
#define TIME_FMT "%Y-%m-%d %H:%M:%S\n"

typedef enum {
	LOG_LEVEL_ERROR = 0, // lowest level
	LOG_LEVEL_WARNING = 1,
	LOG_LEVEL_INFO = 2,
	LOG_LEVEL_DEBUG = 3 // highest level
} LogLevel;

const char *log_level_to_string(LogLevel level);

void app_log(LogLevel level, const char *format, ...);

// Initialize the logger
void logger_init(LogLevel level, const char *file_path);

// Cleanup logger resources
void logger_cleanup(void);
