/*
 * frida-bridge.h
 *
 * Public header for Frida Bridge library. Contains configuration constants,
 * function declarations, and external global variable definitions.
 *
 * This library enables Frida Gadget injection into Android applications
 * running inside container/virtual-space environments without requiring
 * target APK repackaging or device root access.
 */

#ifndef FRIDA_BRIDGE_H
#define FRIDA_BRIDGE_H

#include <jni.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Bridge library base name (without "lib" prefix or ".so" suffix).
 *
 * This is the single source of truth for the bridge's own module/output
 * name. It is NOT used by any dlopen()/loadLibrary() call inside this C
 * codebase (the bridge never looks up its own filename at runtime), but
 * it is picked up by jni/Android.mk via an include, so changing it here
 * changes what `ndk-build` names the output .so.
 *
 * IMPORTANT: after changing this, you must ALSO update every
 * System.loadLibrary("...") / smali `const-string` call in the container
 * app that loads this library (see README section 4, Option A/B) so the
 * name matches exactly.
 */
#define BRIDGE_MODULE_NAME "stealth-bridge"

/** Default seconds to sleep after Application ready before loading gadget. */
#define DEFAULT_DELAY_SECS 0

/** Subdirectory under getFilesDir() that holds gadget files. */
#define GADGET_SUBDIR "stealth"

/** Gadget shared library filename. */
#define GADGET_LIB_NAME "libstealth.so"

/** Gadget config filename (named .so to avoid APK stripping on older Android). */
#define GADGET_CONFIG_NAME "libstealth.cfg.so"

/** Gadget agent script filename. Must match "path" field in config JSON. */
#define GADGET_SCRIPT_NAME "libstealth.scr.so"

/** Bridge-specific config file for runtime settings (e.g. delay). */
#define BRIDGE_CFG_FILE "stealth.cfg"

/** Maximum seconds to wait for JavaVM to become available. */
#define JVM_WAIT_SECS 10

/** Maximum seconds to wait for ART (libart.so) to be mapped into the process. */
#define ART_WAIT_SECS 10

/** Maximum accepted value for the "delay=" setting in frida-bridge.cfg. */
#define MAX_DELAY_SECS 60

/* ═══════════════════════════════════════════════════════════════════════════
 * External Global Variables
 *
 * Declared here, defined in frida-bridge.c with appropriate synchronization.
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Global JavaVM reference, set by JNI_OnLoad. */
extern JavaVM * volatile g_jvm;

/** Idempotency guard to prevent double-spawning of bridge worker thread. */
extern int volatile g_bridge_started;

/** Synchronization mutex for fork-safe operations. */
extern pthread_mutex_t g_bridge_lock;

/* ═══════════════════════════════════════════════════════════════════════════
 * Public Function Declarations
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * JNI_OnLoad() - JNI entry point called when library is loaded by Java.
 *
 * Saves the JavaVM pointer and triggers the bridge worker thread.
 * Called automatically by the Android runtime once per process.
 *
 * @vm:       JavaVM pointer provided by the Android runtime.
 * @reserved: Unused, reserved for future use.
 * @return:   Minimum required JNI version.
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved);

/**
 * bridge_thread - Main bridge initialization worker thread.
 *
 * Runs in a detached background thread. Performs the full initialization
 * sequence: JVM waiting, files dir resolution, gadget loading, sync.
 *
 * @arg:  Unused (required by pthread_create signature).
 * @return: Always NULL (detached thread).
 *
 * Called from ensure_bridge_started() in fork-safety.c.
 */
void *bridge_thread(void *arg);

#endif /* FRIDA_BRIDGE_H */
