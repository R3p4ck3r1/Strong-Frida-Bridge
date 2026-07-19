/*
 * app-detection.c
 *
 * Application detection and file directory resolution via JNI reflection.
 *
 * This module handles the complex task of finding the correct Android
 * Application context in multi-process container environments, with
 * timing-aware polling to handle race conditions between proxy and
 * target applications.
 */

#include <jni.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>

#include "frida-bridge.h"
#include "debug-logging.h"
#include "jni-helpers.h"

extern int is_target_app_ready(const char *files_dir);

/* ═══════════════════════════════════════════════════════════════════════════
 * JNI File Directory Extraction
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * extract_files_dir_from_app - Extract getFilesDir().getAbsolutePath() from jobject.
 *
 * Calls Context.getFilesDir().getAbsolutePath() via JNI reflection on a
 * given Application/Context jobject.
 *
 * This function has no retry logic—it attempts a single extraction and
 * succeeds or fails. Used both for payload probing and final result extraction.
 *
 * All JNI references are carefully managed:
 * - Local refs are deleted in error paths and at cleanup.
 * - String refs are released before deletion.
 * - No orphaned or stale references are left behind.
 *
 * @env:      JNI environment pointer.
 * @app:      Application/Context jobject to query.
 * @out_buf:  Output buffer for the absolute path.
 * @out_sz:   Size of @out_buf.
 * @return:   1 on success with path in @out_buf, 0 on failure (out_buf cleared).
 */
static int extract_files_dir_from_app(JNIEnv *env, jobject app,
                                       char *out_buf, size_t out_sz) {
  if (!env || !app || !out_buf || !out_sz) return 0;

  out_buf[0] = '\0';

  /* Find android.content.Context class. */
  jclass cls_ctx = (*env)->FindClass(env, "android/content/Context");
  if (!cls_ctx) {
    JNI_CLEAR_EXCEPTION(env);
    return 0;
  }

  /* Get getFilesDir() method ID. */
  jmethodID mid_gfd = (*env)->GetMethodID(env, cls_ctx, "getFilesDir", 
                                           "()Ljava/io/File;");
  if (!mid_gfd) {
    JNI_CLEAR_EXCEPTION(env);
    (*env)->DeleteLocalRef(env, cls_ctx);
    return 0;
  }

  /* Call app.getFilesDir() to get File object. */
  jobject file = (*env)->CallObjectMethod(env, app, mid_gfd);
  JNI_CLEAR_EXCEPTION(env);
  if (!file) {
    (*env)->DeleteLocalRef(env, cls_ctx);
    return 0;
  }

  /* Find java.io.File class. */
  jclass cls_file = (*env)->FindClass(env, "java/io/File");
  if (!cls_file) {
    JNI_CLEAR_EXCEPTION(env);
    (*env)->DeleteLocalRef(env, file);
    (*env)->DeleteLocalRef(env, cls_ctx);
    return 0;
  }

  /* Get getAbsolutePath() method ID. */
  jmethodID mid_gap = (*env)->GetMethodID(env, cls_file, "getAbsolutePath", 
                                           "()Ljava/lang/String;");
  if (!mid_gap) {
    JNI_CLEAR_EXCEPTION(env);
    (*env)->DeleteLocalRef(env, cls_file);
    (*env)->DeleteLocalRef(env, file);
    (*env)->DeleteLocalRef(env, cls_ctx);
    return 0;
  }

  /* Call file.getAbsolutePath() to get path string. */
  jstring path_str = (jstring)(*env)->CallObjectMethod(env, file, mid_gap);
  JNI_CLEAR_EXCEPTION(env);

  int ok = 0;
  if (path_str) {
    const char *chars = (*env)->GetStringUTFChars(env, path_str, NULL);
    if (chars && chars[0]) {
      strncpy(out_buf, chars, out_sz - 1);
      out_buf[out_sz - 1] = '\0';
      ok = 1;
      LOGD("extract_files_dir_from_app: extracted path '%s'", out_buf);
    }
    if (chars)
      (*env)->ReleaseStringUTFChars(env, path_str, chars);
    (*env)->DeleteLocalRef(env, path_str);
  }

  /* Clean up all local references. */
  (*env)->DeleteLocalRef(env, cls_file);
  (*env)->DeleteLocalRef(env, file);
  (*env)->DeleteLocalRef(env, cls_ctx);

  return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Application Polling with Timing-Aware Logic
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * get_files_dir_jni - Obtain the target application's files directory.
 *
 * Polls ActivityThread.currentApplication() for up to 30 seconds, looking
 * for an Application that contains the expected payload marker
 * (GADGET_SUBDIR presence).
 *
 * TIMING-AWARE BEHAVIOR:
 * In container environments, currentApplication() may return a proxy/container
 * Application before the real target Application is loaded. This function
 * implements intelligent early-exit logic:
 *
 *   - Payload check happens BEFORE accepting any Application.
 *   - If the same non-payload Application appears twice, it assumes no
 *     progress is being made and exits early instead of waiting the full
 *     30 seconds.
 *   - This prevents the bridge from blocking indefinitely on a proxy app
 *     when the real target hasn't loaded yet.
 *
 * JNI Reference Management:
 *   - g_last_app_seen is a function-local variable using a global JNI ref
 *     internally. Properly deleted with DeleteGlobalRef at cleanup.
 *   - All local refs (app, cls_at) are deleted in error/cleanup paths.
 *
 * @out_buf:  Output buffer for the files directory path.
 * @out_sz:   Size of @out_buf.
 * @return:   1 on success with path in @out_buf, 0 on failure.
 */
int get_files_dir_jni(char *out_buf, size_t out_sz) {
  if (!out_buf || !out_sz) return 0;

  /* Get the global JavaVM reference set by JNI_OnLoad. */
  JavaVM *jvm = g_jvm;
  if (!jvm) {
    LOGW("get_files_dir_jni: g_jvm is NULL, JavaVM not initialized");
    return 0;
  }

  JNIEnv *env = NULL;
  int attached = 0;
  int result = 0;

  /* Get or attach to the JNI environment. */
  jint rc = (*jvm)->GetEnv(jvm, (void **)&env, JNI_VERSION_1_6);
  if (rc == JNI_EDETACHED) {
    if ((*jvm)->AttachCurrentThread(jvm, &env, NULL) != JNI_OK) {
      LOGW("get_files_dir_jni: AttachCurrentThread failed");
      return 0;
    }
    attached = 1;
  } else if (rc != JNI_OK) {
    LOGW("get_files_dir_jni: GetEnv failed with code %d", rc);
    return 0;
  }

  jclass cls_at = NULL;
  jmethodID mid_ca = NULL;
  jobject app = NULL;
  jobject g_last_app_seen = NULL;

  /* Find ActivityThread class. */
  cls_at = (*env)->FindClass(env, "android/app/ActivityThread");
  if (!cls_at) {
    JNI_CLEAR_EXCEPTION(env);
    goto jni_done;
  }

  /* Get currentApplication() static method ID. */
  mid_ca = (*env)->GetStaticMethodID(env, cls_at, "currentApplication", 
                                      "()Landroid/app/Application;");
  if (!mid_ca) {
    JNI_CLEAR_EXCEPTION(env);
    goto jni_done;
  }

  /*
   * POLLING LOOP: Wait for an Application with the payload marker.
   *
   * For each iteration:
   *   1. Call currentApplication() to get the current app.
   *   2. Extract its files dir path.
   *   3. Check for payload marker (GADGET_SUBDIR).
   *   4. If found: accept and return.
   *   5. If not found but new app: create global ref to track it for next iteration.
   *   6. If not found and SAME app: exit early (no progress).
   */
  for (int i = 0; i < 30; ++i) {
    if (app) {
      (*env)->DeleteLocalRef(env, app);
      app = NULL;
    }

    /* Call currentApplication(). */
    app = (*env)->CallStaticObjectMethod(env, cls_at, mid_ca);
    JNI_CLEAR_EXCEPTION(env);

    if (app) {
      char candidate_path[PATH_MAX] = {0};

      /* Try to extract this application's files directory. */
      if (extract_files_dir_from_app(env, app, candidate_path, 
                                      sizeof(candidate_path))) {
        /* Check if this application has the payload marker. */
        if (is_target_app_ready(candidate_path)) {
          /* SUCCESS: This is the target application with payload. */
          strncpy(out_buf, candidate_path, out_sz - 1);
          out_buf[out_sz - 1] = '\0';
          result = 1;
          LOGI("get_files_dir_jni: target application found at '%s'", out_buf);
          break;
        }

        /* No payload in this candidate. Check if it's the same app again. */
        int is_same_as_last = (g_last_app_seen && 
                               (*env)->IsSameObject(env, app, g_last_app_seen));

        if (is_same_as_last) {
          /*
           * EARLY EXIT: Same application, still no payload.
           * This means no new applications have loaded since the last poll.
           * Waiting longer won't help. Accept this path and return;
           * the natural abort check (missing gadget file) will trigger.
           */
          LOGD("get_files_dir_jni: same application seen twice without payload, exiting early");
          strncpy(out_buf, candidate_path, out_sz - 1);
          out_buf[out_sz - 1] = '\0';
          result = 1;
          break;
        }

        /* Different application, no payload yet. Keep waiting for target. */
        LOGD("get_files_dir_jni: candidate '%s' lacks payload, continuing poll", 
             candidate_path);

        /* Remember this application for next iteration's comparison. */
        if (g_last_app_seen)
          (*env)->DeleteGlobalRef(env, g_last_app_seen);
        g_last_app_seen = (*env)->NewGlobalRef(env, app);
      }

      app = NULL; /* Clear local ref, will re-fetch next iteration. */
    }

    /* Log progress at intervals. */
    if (i % 5 == 0)
      LOGD("get_files_dir_jni: polling for target application with payload (%d/30)...", i);

    sleep(1);
  }

  /* If polling completed without finding target. */
  if (!result && !app) {
    LOGW("get_files_dir_jni: no application with payload found after 30 seconds");
    goto jni_done;
  }

jni_done:
  /* Clean up all JNI references. */
  if (app)
    (*env)->DeleteLocalRef(env, app);
  if (g_last_app_seen)
    (*env)->DeleteGlobalRef(env, g_last_app_seen);
  if (cls_at)
    (*env)->DeleteLocalRef(env, cls_at);
  if (attached)
    (*jvm)->DetachCurrentThread(jvm);

  return result;
}
