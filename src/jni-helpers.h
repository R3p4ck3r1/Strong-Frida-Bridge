/*
 * jni-helpers.h
 *
 * JNI helper macros and inline utility functions for safe and consistent
 * JNI exception handling and reference management.
 */

#ifndef JNI_HELPERS_H
#define JNI_HELPERS_H

#include <jni.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * JNI Exception Handling Macro
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * JNI_CLEAR_EXCEPTION - Clear any pending JNI exceptions.
 *
 * After a JNI call fails or throws an exception, the JNI environment enters
 * an error state. This macro clears that state to allow subsequent JNI calls.
 * Safe to call even if no exception is pending.
 *
 * Usage:
 *   jclass cls = (*env)->FindClass(env, "com/example/Class");
 *   if (!cls) {
 *     JNI_CLEAR_EXCEPTION(env);
 *     return 0; // or handle error
 *   }
 */
#define JNI_CLEAR_EXCEPTION(env) \
  do { \
    if ((env) && (*env)->ExceptionCheck(env)) \
      (*env)->ExceptionClear(env); \
  } while (0)

/* ═══════════════════════════════════════════════════════════════════════════
 * Inline Helper Functions
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * jni_safe_delete_local_ref - Safely delete a local JNI reference.
 *
 * Checks for NULL before deleting and clears the reference pointer.
 * Prevents double-deletion and stale references.
 *
 * @env:     JNI environment pointer.
 * @ref:     Pointer to the reference to delete (will be set to NULL).
 *
 * Example:
 *   jstring str = (*env)->NewStringUTF(env, "hello");
 *   // ... use str ...
 *   jni_safe_delete_local_ref(env, &str);
 */
static inline void jni_safe_delete_local_ref(JNIEnv *env, jobject *ref) {
  if (env && ref && *ref) {
    (*env)->DeleteLocalRef(env, *ref);
    *ref = NULL;
  }
}

/**
 * jni_safe_delete_global_ref - Safely delete a global JNI reference.
 *
 * Checks for NULL before deleting and clears the reference pointer.
 * Global refs must be cleaned up explicitly to prevent memory leaks.
 *
 * @env:     JNI environment pointer.
 * @ref:     Pointer to the reference to delete (will be set to NULL).
 *
 * Example:
 *   jobject global_app = (*env)->NewGlobalRef(env, app);
 *   // ... use global_app ...
 *   jni_safe_delete_global_ref(env, &global_app);
 */
static inline void jni_safe_delete_global_ref(JNIEnv *env, jobject *ref) {
  if (env && ref && *ref) {
    (*env)->DeleteGlobalRef(env, *ref);
    *ref = NULL;
  }
}

#endif /* JNI_HELPERS_H */
