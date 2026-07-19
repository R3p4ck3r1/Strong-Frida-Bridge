/*
 * fork-safety.c
 *
 * Fork-safety mechanisms and idempotent worker thread spawning.
 *
 * When a process forks, threads do not survive in the child process;
 * only the calling thread continues. This module implements handlers
 * to reset bridge state post-fork and respawn the worker thread in
 * the child process, ensuring each process initializes independently.
 */

#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "frida-bridge.h"
#include "debug-logging.h"

/**
 * Forward declaration of ensure_bridge_started, defined later in this file.
 * Called from on_fork_child().
 */
void ensure_bridge_started(void);

/* Forward declaration of bridge_thread (defined in frida-bridge.c). */
extern void *bridge_thread(void *arg);

/* ═══════════════════════════════════════════════════════════════════════════
 * Fork Handlers
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * on_fork_prepare - Called in parent process before fork().
 *
 * Acquires the bridge lock to ensure no worker thread is being spawned
 * at the moment of fork. This prevents inconsistent state in the child.
 *
 * Called automatically by pthread_atfork().
 */
static void on_fork_prepare(void) {
  pthread_mutex_lock(&g_bridge_lock);
}

/**
 * on_fork_parent - Called in parent process after fork().
 *
 * Releases the bridge lock so the parent process can continue normally.
 *
 * Called automatically by pthread_atfork().
 */
static void on_fork_parent(void) {
  pthread_mutex_unlock(&g_bridge_lock);
}

/**
 * on_fork_child - Called in child process after fork().
 *
 * Resets bridge state and respawns the worker thread.
 *
 * In the child process:
 *   - The worker thread from the parent is GONE (threads don't survive fork).
 *   - The atomic flags from parent are inherited as stale values.
 *   - The JavaVM pointer (g_jvm) is still valid (inherited memory).
 *   - The mutex is in an undefined state and must be unlocked in child.
 *
 * Actions:
 *   1. Reset g_bridge_started to allow worker to start fresh.
 *   2. Unlock the mutex (in child init state).
 *   3. Call ensure_bridge_started() to spawn a new worker for the child.
 *
 * Called automatically by pthread_atfork().
 */
static void on_fork_child(void) {
  LOGD("on_fork_child: child process post-fork, resetting bridge state");
  
  /* Reset the started flag so the worker can spawn in the child. */
  g_bridge_started = 0;
  
  /* Unlock the mutex (it's in unknown state post-fork; this initializes it). */
  pthread_mutex_unlock(&g_bridge_lock);
  
  /* Respawn the worker thread in the child process. */
  ensure_bridge_started();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Idempotent Worker Spawning
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * ensure_bridge_started - Idempotently spawn the bridge worker thread.
 *
 * This function is called from multiple places:
 *   - lib_constructor() (when .so is loaded)
 *   - JNI_OnLoad() (fallback, if constructor's spawn failed)
 *   - on_fork_child() (after fork, to respawn in child)
 *
 * Uses atomic compare-and-swap to ensure only the FIRST caller succeeds
 * in spawning the worker thread. Subsequent calls are no-ops.
 *
 * If pthread_create() fails:
 *   - The flag is reset to allow retry.
 *   - An error is logged, but the process continues.
 *   - JNI_OnLoad() may retry on the next trigger.
 *
 * Protection: Holds g_bridge_lock during the actual pthread_create(),
 * preventing races with fork().
 */
void ensure_bridge_started(void) {
  /*
   * Atomic compare-and-swap: if g_bridge_started == 0, set to 1 and proceed.
   * Otherwise, another thread/call already triggered, so just return.
   */
  // int expected = 0;
  if (__sync_bool_compare_and_swap(&g_bridge_started, 0, 1) == 0) {
    /* Already started by another caller. */
    return;
  }

  /* Acquire lock to protect pthread_create() against fork(). */
  pthread_mutex_lock(&g_bridge_lock);

  pthread_t t;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  if (pthread_create(&t, &attr, bridge_thread, NULL) != 0) {
    LOGE("ensure_bridge_started: pthread_create failed: %s", strerror(errno));
    /* Reset flag to allow retry later. */
    g_bridge_started = 0;
  } else {
    LOGD("ensure_bridge_started: worker thread spawned successfully");
  }

  pthread_attr_destroy(&attr);
  pthread_mutex_unlock(&g_bridge_lock);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Fork Handler Registration
 *
 * Exposed as a non-static function so lib_constructor() can call it.
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * register_fork_handlers - Register fork-safety handlers.
 *
 * Installs the prepare/parent/child handlers via pthread_atfork().
 * Should be called once during library initialization (from lib_constructor).
 *
 * This MUST be called before any threads are spawned, to ensure
 * the fork handlers are registered in the process.
 */
void register_fork_handlers(void) {
  if (pthread_atfork(on_fork_prepare, on_fork_parent, on_fork_child) != 0) {
    LOGW("register_fork_handlers: pthread_atfork failed (may be in child process)");
  } else {
    LOGD("register_fork_handlers: fork handlers registered successfully");
  }
}
