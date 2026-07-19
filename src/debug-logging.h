/*
 * debug-logging.h
 *
 * Production-grade logging macros for Frida Bridge.
 * Supports conditional compilation for debug vs. release builds.
 *
 * Build with -DFRIDA_BRIDGE_DEBUG to enable verbose debug logging.
 * Release builds (default) emit only INFO, WARN, and ERROR messages.
 */

#ifndef DEBUG_LOGGING_H
#define DEBUG_LOGGING_H

#include <android/log.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Logging Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

#define LOG_TAG "FridaBridge"

/* ═══════════════════════════════════════════════════════════════════════════
 * Public Logging Macros
 *
 * LOGI: Informational messages (important events, state changes).
 * LOGW: Warning messages (unexpected but non-fatal conditions).
 * LOGE: Error messages (failures, aborts).
 * LOGD: Debug messages (verbose diagnostics, only in debug build).
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * LOGI - Log an informational message.
 * Used for important state transitions and successful operations.
 */
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/**
 * LOGW - Log a warning message.
 * Used for recoverable errors and unexpected conditions.
 */
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

/**
 * LOGE - Log an error message.
 * Used for failures that require immediate attention.
 */
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/**
 * LOGD - Log a debug message.
 * Only compiled in when -DFRIDA_BRIDGE_DEBUG is specified.
 * Used for detailed diagnostic information during development and troubleshooting.
 */
#ifdef FRIDA_BRIDGE_DEBUG
# define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#else
# define LOGD(...)((void) 0)
#endif

#endif /* DEBUG_LOGGING_H */
