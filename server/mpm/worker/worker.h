#include "apr_thread_proc.h"

static void *worker_thread(apr_thread_t *thd, void *dummy);
