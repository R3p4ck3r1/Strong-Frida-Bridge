/*
 * frida-bridge.c
 *
 * Main Frida Bridge implementation.
 *
 * Provides core functionality for gadget loading, file management, and
 * Android integration. Includes the bridge worker thread, library entry
 * points, and debugging utilities.
 */

#define _GNU_SOURCE
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <dirent.h>
#include <linux/limits.h>
#include <stdatomic.h>
#include <pthread.h>

#include "frida-bridge.h"
#include "debug-logging.h"
#include "jni-helpers.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Global Variables
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Global JavaVM reference, set by JNI_OnLoad. */
JavaVM * volatile g_jvm = NULL;

/** Idempotency guard for worker thread spawning. */
int volatile g_bridge_started = 0;

/** Synchronization mutex for fork safety. */
pthread_mutex_t g_bridge_lock = PTHREAD_MUTEX_INITIALIZER;

/* ═══════════════════════════════════════════════════════════════════════════
 * Forward Declarations
 * ═══════════════════════════════════════════════════════════════════════════ */

extern int get_files_dir_jni(char *out_buf, size_t out_sz);
extern void read_package_name(char *buf, size_t sz);
extern int wait_for_art(int max_secs);
extern int resolve_dir_from_maps(const char *libname, char *out_dir, size_t sz);
extern void register_fork_handlers(void);
extern void ensure_bridge_started(void);

/* ═══════════════════════════════════════════════════════════════════════════
 * File I/O Utilities
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * copy_file - Copy a file using low-level file descriptor I/O.
 *
 * Copies the file from @src to @dst with mode 0644 (rw-r--r--).
 * If src and dst are the same path, the copy is skipped silently.
 * Uses buffered read/write for efficiency.
 *
 * @src:     Absolute path of the source file to copy.
 * @dst:     Absolute path of the destination file to create.
 * @return:  1 on success, 0 on failure (with error logged).
 */
static int copy_file(const char *src, const char *dst) {
  if (!src || !dst) return 0;

  if (strcmp(src, dst) == 0) {
    LOGD("copy_file: source and destination are identical, skipping");
    return 1;
  }

  int sfd = open(src, O_RDONLY);
  if (sfd < 0) {
    LOGE("copy_file: cannot open source '%s': %s", src, strerror(errno));
    return 0;
  }

  int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (dfd < 0) {
    LOGE("copy_file: cannot open destination '%s': %s", dst, strerror(errno));
    close(sfd);
    return 0;
  }

  char buf[8192];
  ssize_t n;
  int ok = 1;

  /* Copy in chunks. */
  while ((n = read(sfd, buf, sizeof(buf))) > 0) {
    ssize_t w = 0;
    while (w < n) {
      ssize_t r = write(dfd, buf + w, (size_t)(n - w));
      if (r <= 0) {
        ok = 0;
        break;
      }
      w += r;
    }
    if (!ok) break;
  }

  close(sfd);
  close(dfd);

  if (ok) {
    LOGD("copy_file: successfully copied '%s' -> '%s'", src, dst);
  } else {
    LOGE("copy_file: write error while copying to '%s'", dst);
  }

  return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration Management
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * write_config_with_relative_script_path - Write gadget config with relative paths.
 *
 * Reads the source config JSON, rewrites the "path" field to a relative
 * filename (GADGET_SCRIPT_NAME), and writes to destination.
 *
 * Frida Gadget resolves relative paths from its own directory (real path).
 * Absolute paths fail in containers due to path remapping.
 *
 * If no "path" key exists, the file is copied verbatim.
 *
 * @src_config:  Path to source config file (logical path).
 * @dst_config:  Path to write fixed config (real/container path).
 * @return:      1 on success, 0 on failure.
 */
static int write_config_with_relative_script_path(const char *src_config,
                                                   const char *dst_config) {
  if (!src_config || !dst_config) return 0;

  int fd = open(src_config, O_RDONLY);
  if (fd < 0) {
    LOGE("write_config: cannot open source '%s': %s", src_config, strerror(errno));
    return 0;
  }

  char buf[4096] = {0};
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);

  if (n <= 0) {
    LOGE("write_config: read failed for '%s'", src_config);
    return 0;
  }
  buf[n] = '\0';

  LOGD("write_config: read config (%.256s...)", buf);

  /* Find "path" key. If absent, copy verbatim (listen mode config). */
  char *path_key = strstr(buf, "\"path\"");
  if (!path_key) {
    LOGD("write_config: no 'path' key found, copying verbatim");
    return copy_file(src_config, dst_config);
  }

  /* Find the opening quote of the path value. */
  char *q1 = strchr(path_key + 6, '"');
  if (!q1) {
    LOGW("write_config: malformed path value, copying verbatim");
    return copy_file(src_config, dst_config);
  }
  q1++;

  /* Find the closing quote. */
  char *q2 = strchr(q1, '"');
  if (!q2) {
    LOGW("write_config: unclosed path string, copying verbatim");
    return copy_file(src_config, dst_config);
  }

  /* Construct new config with relative path. */
  char new_cfg[4096] = {0};
  size_t pre = (size_t)(q1 - buf);
  size_t slen = strlen(GADGET_SCRIPT_NAME);
  size_t post = (size_t)(n - (q2 - buf));
  size_t total = pre + slen + post;

  if (total >= sizeof(new_cfg)) {
    LOGW("write_config: rewritten config too large, copying verbatim");
    return copy_file(src_config, dst_config);
  }

  memcpy(new_cfg, buf, pre);
  memcpy(new_cfg + pre, GADGET_SCRIPT_NAME, slen);
  memcpy(new_cfg + pre + slen, q2, post);

  LOGD("write_config: rewritten (%.256s...)", new_cfg);

  /* Write rewritten config. */
  int dfd = open(dst_config, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (dfd < 0) {
    LOGE("write_config: cannot open destination '%s': %s", dst_config, strerror(errno));
    return 0;
  }

  ssize_t w = write(dfd, new_cfg, total);
  close(dfd);

  if (w != (ssize_t)total) {
    LOGE("write_config: incomplete write to '%s'", dst_config);
    return 0;
  }

  LOGD("write_config: successfully written to '%s'", dst_config);
  return 1;
}

/**
 * read_bridge_cfg - Read bridge configuration from frida-bridge.cfg.
 *
 * Parses the bridge config file for a "delay=N" setting (0-60 seconds).
 * This delay is applied after the Application is ready but before gadget
 * loading, allowing app initialization to progress further.
 *
 * Falls back to DEFAULT_DELAY_SECS if the file is missing, unreadable,
 * or contains invalid values.
 *
 * @frida_dir:  Path to the frida subdirectory.
 * @return:     Delay in seconds (0-60, or DEFAULT_DELAY_SECS on error).
 */
static int read_bridge_cfg(const char *frida_dir) {
  if (!frida_dir) return DEFAULT_DELAY_SECS;

  char cfg_path[PATH_MAX];
  snprintf(cfg_path, sizeof(cfg_path), "%s/%s", frida_dir, BRIDGE_CFG_FILE);

  int fd = open(cfg_path, O_RDONLY);
  if (fd < 0) {
    LOGD("read_bridge_cfg: config file not found, using default %d seconds",
         DEFAULT_DELAY_SECS);
    return DEFAULT_DELAY_SECS;
  }

  char buf[64] = {0};
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);

  if (n <= 0)
    return DEFAULT_DELAY_SECS;

  buf[n] = '\0';

  /* Parse "delay=N" */
  char *p = strstr(buf, "delay=");
  if (p) {
    int v = atoi(p + 6);
    if (v >= 0 && v <= MAX_DELAY_SECS) {
      LOGD("read_bridge_cfg: parsed delay = %d seconds", v);
      return v;
    }
  }

  LOGW("read_bridge_cfg: parse error or out of range, using default %d seconds",
       DEFAULT_DELAY_SECS);
  return DEFAULT_DELAY_SECS;
}

/**
 * ensure_files_at_real_path - Sync config and script to real gadget directory.
 *
 * After dlopen loads the gadget, its real (container-remapped) directory
 * is determined via /proc/self/maps. This function ensures that the
 * config and script files are present at this real path so that Frida
 * Gadget can find them on the NEXT launch.
 *
 * Files are only copied if they don't already exist at the real path,
 * preserving any manual updates the user may have made.
 *
 * On the first launch, this typically does nothing (gadget hasn't initialized).
 * On the second launch, config and script are already present.
 *
 * @real_dir:        Real (container-remapped) gadget directory from maps.
 * @logical_config:  Logical path of the config file (user-maintained source).
 * @logical_script:  Logical path of the script file (user-maintained source).
 */
static void ensure_files_at_real_path(const char *real_dir,
                                       const char *logical_config,
                                       const char *logical_script) {
  if (!real_dir) return;

  char real_config[PATH_MAX];
  char real_script[PATH_MAX];

  snprintf(real_config, sizeof(real_config), "%s/%s", real_dir, GADGET_CONFIG_NAME);
  snprintf(real_script, sizeof(real_script), "%s/%s", real_dir, GADGET_SCRIPT_NAME);

  /* Handle config file. */
  if (access(real_config, F_OK) == 0) {
    LOGD("ensure_files_at_real_path: config already exists at real path, skipping");
  } else if (logical_config && access(logical_config, F_OK) == 0) {
    if (write_config_with_relative_script_path(logical_config, real_config)) {
      LOGI("ensure_files_at_real_path: config deployed to real path");
    } else {
      LOGE("ensure_files_at_real_path: config deployment failed");
    }
  } else {
    LOGW("ensure_files_at_real_path: config not found at logical path");
  }

  /* Handle script file. */
  if (access(real_script, F_OK) == 0) {
    LOGD("ensure_files_at_real_path: script already exists at real path, skipping");
  } else if (logical_script && access(logical_script, F_OK) == 0) {
    if (copy_file(logical_script, real_script)) {
      LOGI("ensure_files_at_real_path: script deployed to real path");
    } else {
      LOGE("ensure_files_at_real_path: script deployment failed");
    }
  } else {
    LOGD("ensure_files_at_real_path: script not found at logical path (script mode inactive)");
  }

  /* Log final status. */
  LOGI("ensure_files_at_real_path: real path status — config:[%s] script:[%s]",
       access(real_config, F_OK) == 0 ? "OK" : "MISSING",
       access(real_script, F_OK) == 0 ? "OK" : "MISSING");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Debug Logging Utilities
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifdef FRIDA_BRIDGE_DEBUG
/**
 * dbg_log_gadget_maps - Log all /proc/self/maps entries for the gadget.
 *
 * Useful for debugging path resolution issues in containers.
 */
static void dbg_log_gadget_maps(void) {
  FILE *f = fopen("/proc/self/maps", "r");
  if (!f) return;

  char line[512];
  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, GADGET_LIB_NAME)) continue;

    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
      line[len - 1] = '\0';

    LOGD("dbg_maps: %s", line);
  }

  fclose(f);
}

/**
 * dbg_log_real_dir_contents - Log files in the real gadget directory.
 */
static void dbg_log_real_dir_contents(const char *real_dir) {
  if (!real_dir) return;

  DIR *dr = opendir(real_dir);
  if (!dr) {
    LOGD("dbg_dir: opendir failed: %s", strerror(errno));
    return;
  }

  struct dirent *de;
  while ((de = readdir(dr)) != NULL) {
    if (de->d_name[0] == '.') continue;

    char fpath[PATH_MAX];
    struct stat st;
    snprintf(fpath, sizeof(fpath), "%s/%s", real_dir, de->d_name);
    stat(fpath, &st);

    LOGD("dbg_dir: %-40s  size=%-10lld  mode=%04o",
         de->d_name, (long long)st.st_size, st.st_mode & 07777);
  }

  closedir(dr);
}
#else
static void dbg_log_gadget_maps(void) {}
static void dbg_log_real_dir_contents(const char *d) { (void)d; }
#endif /* FRIDA_BRIDGE_DEBUG */

/* ═══════════════════════════════════════════════════════════════════════════
 * Main Bridge Worker Thread
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * bridge_thread - Main bridge initialization and gadget loading sequence.
 *
 * Runs in a detached background thread to avoid blocking the process.
 *
 * Sequence:
 *   1. Wait for JavaVM to be initialized by JNI_OnLoad.
 *   2. Resolve the target application's files directory via JNI.
 *   3. Construct paths for gadget, config, and script files.
 *   4. Verify gadget exists; abort if missing.
 *   5. Read startup delay from bridge config.
 *   6. Sleep for configured delay (post-Application-ready).
 *   7. Wait for ART (libart.so) to be present.
 *   8. dlopen the gadget (kernel remaps logical path to real path).
 *   9. Resolve real gadget directory from /proc/self/maps.
 *  10. Sync config and script to real path for next launch.
 *  11. Log completion and environment type (container vs. native).
 *
 * @arg:  Unused, required by pthread_create signature.
 * @return: Always NULL (detached thread).
 */
void *bridge_thread(void *arg) {
  (void)arg;

  LOGI("bridge_thread: initialization started");

  /* 1. Wait for JavaVM. */
  int waited = 0;
  while (!g_jvm && waited++ < JVM_WAIT_SECS) {
    sleep(1);
  }
  if (!g_jvm) {
    LOGE("bridge_thread: JavaVM unavailable after %d seconds, aborting",
         JVM_WAIT_SECS);
    return NULL;
  }

  /* 2. Resolve target application's files directory. */
  char files_dir[PATH_MAX] = {0};
  if (!get_files_dir_jni(files_dir, sizeof(files_dir))) {
    char pkg[256] = {0};
    read_package_name(pkg, sizeof(pkg));

    if (strcmp(pkg, "unknown") == 0) {
      LOGE("bridge_thread: cannot determine files directory, aborting");
      return NULL;
    }

    snprintf(files_dir, sizeof(files_dir), "/data/data/%s/files", pkg);
    LOGW("bridge_thread: JNI failed, using fallback files dir: %s", files_dir);
  }

  LOGI("bridge_thread: target files directory: %s", files_dir);

  /* 3. Construct logical paths. */
  char logical_frida[PATH_MAX];
  char logical_gadget[PATH_MAX];
  char logical_config[PATH_MAX];
  char logical_script[PATH_MAX];

  snprintf(logical_frida, sizeof(logical_frida), "%s/%s", files_dir, GADGET_SUBDIR);
  snprintf(logical_gadget, sizeof(logical_gadget), "%s/%s", logical_frida, GADGET_LIB_NAME);
  snprintf(logical_config, sizeof(logical_config), "%s/%s", logical_frida, GADGET_CONFIG_NAME);
  snprintf(logical_script, sizeof(logical_script), "%s/%s", logical_frida, GADGET_SCRIPT_NAME);

  /* 4. Verify gadget exists. */
  if (access(logical_gadget, F_OK) != 0) {
    LOGE("bridge_thread: gadget not found at '%s', aborting", logical_gadget);
    return NULL;
  }

  /* 5. Read startup delay. */
  int delay = read_bridge_cfg(logical_frida);

  /* 6. Apply post-Application-ready delay. */
  if (delay > 0) {
    LOGD("bridge_thread: applying post-init delay of %d seconds", delay);
    sleep(delay);
  }

  /* 7. Wait for ART. */
  if (!wait_for_art(ART_WAIT_SECS)) {
    LOGW("bridge_thread: ART not detected; loading gadget anyway (may fail)");
  }

  /* 8. Load gadget. */
  LOGD("bridge_thread: dlopen: '%s'", logical_gadget);
  void *handle = dlopen(logical_gadget, RTLD_NOW | RTLD_GLOBAL);
  if (!handle) {
    LOGE("bridge_thread: dlopen failed: %s", dlerror());
    return NULL;
  }

  LOGI("bridge_thread: gadget loaded successfully");
  dbg_log_gadget_maps();

  /* 9. Resolve real gadget directory. */
  char real_dir[PATH_MAX] = {0};
  if (!resolve_dir_from_maps(GADGET_LIB_NAME, real_dir, sizeof(real_dir))) {
    LOGE("bridge_thread: cannot resolve real gadget directory from maps");
    return NULL;
  }

  LOGD("bridge_thread: real gadget directory: %s", real_dir);
  dbg_log_real_dir_contents(real_dir);

  /* 10. Sync config and script to real path. */
  ensure_files_at_real_path(real_dir, logical_config, logical_script);

  /* 11. Report environment type. */
  int in_container = (strcmp(real_dir, logical_frida) != 0);
  if (in_container) {
    LOGI("bridge_thread: container environment detected; files synced to real path");
  } else {
    LOGI("bridge_thread: native (non-container) environment detected");
  }

  LOGI("bridge_thread: completed successfully");
  return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Library Entry Points
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * lib_constructor - Library constructor, called when .so is loaded.
 *
 * Registers fork-safety handlers and spawns the bridge worker thread.
 * Called automatically by the loader before any other code in the process.
 *
 * Attribute: ((constructor)) ensures this runs at library load time.
 */
__attribute__((constructor))
static void lib_constructor(void) {
  LOGI("lib_constructor: FridaBridge library initializing");
  
  register_fork_handlers();
  ensure_bridge_started();
}

/**
 * JNI_OnLoad - JNI entry point, called when library is loaded by Java.
 *
 * Saves the JavaVM pointer and provides a fallback trigger for worker spawning
 * in case the constructor's attempt failed due to early-init timing constraints.
 *
 * Called automatically by the Android runtime once per process.
 *
 * @vm:       JavaVM pointer provided by the Android runtime.
 * @reserved: Reserved for future use; unused.
 * @return:   JNI_VERSION_1_6 (minimum supported version).
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)reserved;

  g_jvm = vm;
  LOGD("JNI_OnLoad: JavaVM pointer saved");
  
  /* Fallback trigger in case constructor's spawn attempt failed. */
  ensure_bridge_started();

  return JNI_VERSION_1_6;
}
