#include <stdio.h>

#include "apr.h"
#include "apr_strings.h"
#include "apr_getopt.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "apr_md5.h"
#include "apr_time.h"
#include "apr_thread_proc.h"
#include "apr_version.h"
#include "apu_version.h"

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"
#include "mod_core.h"
#include "http_request.h"
#include "http_vhost.h"
#include "apr_uri.h"
#include "util_ebcdic.h"
#include "ap_mpm.h"

#include "http_connection.h"
#include "http_protocol.h"
#include "apr_arch_threadproc.h"

#include "scoreboard.h"

// server/mpm/mpmt_os2/mpmt_os2.c
// server_rec *ap_server_conf;

// server/mpm/worker/worker.c
/* The structure used to pass unique initialization info to each thread */
static int thread_limit = 0;
typedef struct
{
    int pid;
    int tid;
    int sd;
} proc_info;
#define ID_FROM_CHILD_THREAD(c, t) ((c * thread_limit) + t)

// server/util.c
typedef struct
{
    apr_thread_start_t func;
    void *data;
} thread_ctx;

static apr_pool_t *pconf;    /* Pool for config stuff */
static apr_pool_t *pruntime; /* Pool for MPM threads stuff */
apr_thread_start_t _worker_thread;
apr_thread_start_t _thread_start;

static void show_mpm_settings(void)
{
    int mpm_query_info;
    apr_status_t retval;

    printf("Server MPM:     %s\n", ap_show_mpm());

    retval = ap_mpm_query(AP_MPMQ_IS_THREADED, &mpm_query_info);

    if (retval == APR_SUCCESS)
    {
        printf("  threaded:     ");

        if (mpm_query_info == AP_MPMQ_DYNAMIC)
        {
            printf("yes (variable thread count)\n");
        }
        else if (mpm_query_info == AP_MPMQ_STATIC)
        {
            printf("yes (fixed thread count)\n");
        }
        else
        {
            printf("no\n");
        }
    }

    retval = ap_mpm_query(AP_MPMQ_IS_FORKED, &mpm_query_info);

    if (retval == APR_SUCCESS)
    {
        printf("    forked:     ");

        if (mpm_query_info == AP_MPMQ_DYNAMIC)
        {
            printf("yes (variable process count)\n");
        }
        else if (mpm_query_info == AP_MPMQ_STATIC)
        {
            printf("yes (fixed process count)\n");
        }
        else
        {
            printf("no\n");
        }
    }
}

static void show_compile_settings(void)
{
    printf("Server version: %s\n", ap_get_server_description());
    printf("Server built:   %s\n", ap_get_server_built());
    printf("Server's Module Magic Number: %u:%u\n",
           MODULE_MAGIC_NUMBER_MAJOR, MODULE_MAGIC_NUMBER_MINOR);
#if APR_MAJOR_VERSION >= 2
    printf("Server loaded:  APR %s, PCRE %s\n",
           apr_version_string(), ap_pcre_version_string(AP_REG_PCRE_LOADED));
    printf("Compiled using: APR %s, PCRE %s\n",
           APR_VERSION_STRING, ap_pcre_version_string(AP_REG_PCRE_COMPILED));
#else
    printf("Server loaded:  APR %s, APR-UTIL %s, PCRE %s\n",
           apr_version_string(), apu_version_string(),
           ap_pcre_version_string(AP_REG_PCRE_LOADED));
    printf("Compiled using: APR %s, APR-UTIL %s, PCRE %s\n",
           APR_VERSION_STRING, APU_VERSION_STRING,
           ap_pcre_version_string(AP_REG_PCRE_COMPILED));
#endif
    /* sizeof(foo) is long on some platforms so we might as well
     * make it long everywhere to keep the printf format
     * consistent
     */
    printf("Architecture:   %ld-bit\n", 8 * (long)sizeof(void *));

    show_mpm_settings();

    printf("Server compiled with....\n");
#ifdef BIG_SECURITY_HOLE
    printf(" -D BIG_SECURITY_HOLE\n");
#endif

#ifdef SECURITY_HOLE_PASS_AUTHORIZATION
    printf(" -D SECURITY_HOLE_PASS_AUTHORIZATION\n");
#endif

#ifdef OS
    printf(" -D OS=\"" OS "\"\n");
#endif

#ifdef HAVE_SHMGET
    printf(" -D HAVE_SHMGET\n");
#endif

#if APR_FILE_BASED_SHM
    printf(" -D APR_FILE_BASED_SHM\n");
#endif

#if APR_HAS_SENDFILE
    printf(" -D APR_HAS_SENDFILE\n");
#endif

#if APR_HAS_MMAP
    printf(" -D APR_HAS_MMAP\n");
#endif

#ifdef NO_WRITEV
    printf(" -D NO_WRITEV\n");
#endif

#ifdef NO_LINGCLOSE
    printf(" -D NO_LINGCLOSE\n");
#endif

#if APR_HAVE_IPV6
    printf(" -D APR_HAVE_IPV6 (IPv4-mapped addresses ");
#ifdef AP_ENABLE_V4_MAPPED
    printf("enabled)\n");
#else
    printf("disabled)\n");
#endif
#endif

#if APR_USE_FLOCK_SERIALIZE
    printf(" -D APR_USE_FLOCK_SERIALIZE\n");
#endif

#if APR_USE_SYSVSEM_SERIALIZE
    printf(" -D APR_USE_SYSVSEM_SERIALIZE\n");
#endif

#if APR_USE_POSIXSEM_SERIALIZE
    printf(" -D APR_USE_POSIXSEM_SERIALIZE\n");
#endif

#if APR_USE_FCNTL_SERIALIZE
    printf(" -D APR_USE_FCNTL_SERIALIZE\n");
#endif

#if APR_USE_PROC_PTHREAD_SERIALIZE
    printf(" -D APR_USE_PROC_PTHREAD_SERIALIZE\n");
#endif

#if APR_USE_PTHREAD_SERIALIZE
    printf(" -D APR_USE_PTHREAD_SERIALIZE\n");
#endif

#if APR_PROCESS_LOCK_IS_GLOBAL
    printf(" -D APR_PROCESS_LOCK_IS_GLOBAL\n");
#endif

#ifdef SINGLE_LISTEN_UNSERIALIZED_ACCEPT
    printf(" -D SINGLE_LISTEN_UNSERIALIZED_ACCEPT\n");
#endif

#if APR_HAS_OTHER_CHILD
    printf(" -D APR_HAS_OTHER_CHILD\n");
#endif

#ifdef AP_HAVE_RELIABLE_PIPED_LOGS
    printf(" -D AP_HAVE_RELIABLE_PIPED_LOGS\n");
#endif

#ifdef BUFFERED_LOGS
    printf(" -D BUFFERED_LOGS\n");
#ifdef PIPE_BUF
    printf(" -D PIPE_BUF=%ld\n", (long)PIPE_BUF);
#endif
#endif

    printf(" -D DYNAMIC_MODULE_LIMIT=%ld\n", (long)DYNAMIC_MODULE_LIMIT);

#if APR_CHARSET_EBCDIC
    printf(" -D APR_CHARSET_EBCDIC\n");
#endif

#ifdef NEED_HASHBANG_EMUL
    printf(" -D NEED_HASHBANG_EMUL\n");
#endif

/* This list displays the compiled in default paths: */
#ifdef HTTPD_ROOT
    printf(" -D HTTPD_ROOT=\"" HTTPD_ROOT "\"\n");
#endif

#ifdef SUEXEC_BIN
    printf(" -D SUEXEC_BIN=\"" SUEXEC_BIN "\"\n");
#endif

#ifdef DEFAULT_PIDLOG
    printf(" -D DEFAULT_PIDLOG=\"" DEFAULT_PIDLOG "\"\n");
#endif

#ifdef DEFAULT_SCOREBOARD
    printf(" -D DEFAULT_SCOREBOARD=\"" DEFAULT_SCOREBOARD "\"\n");
#endif

#ifdef DEFAULT_ERRORLOG
    printf(" -D DEFAULT_ERRORLOG=\"" DEFAULT_ERRORLOG "\"\n");
#endif

#ifdef AP_TYPES_CONFIG_FILE
    printf(" -D AP_TYPES_CONFIG_FILE=\"" AP_TYPES_CONFIG_FILE "\"\n");
#endif

#ifdef SERVER_CONFIG_FILE
    printf(" -D SERVER_CONFIG_FILE=\"" SERVER_CONFIG_FILE "\"\n");
#endif
}

#define TASK_SWITCH_SLEEP 10000

static void destroy_and_exit_process(process_rec *process,
                                     int process_exit_value)
{
    /*
     * Sleep for TASK_SWITCH_SLEEP micro seconds to cause a task switch on
     * OS layer and thus give possibly started piped loggers a chance to
     * process their input. Otherwise it is possible that they get killed
     * by us before they can do so. In this case maybe valuable log messages
     * might get lost.
     */
    apr_sleep(TASK_SWITCH_SLEEP);
    ap_main_state = AP_SQ_MS_EXITING;
    apr_pool_destroy(process->pool); /* and destroy all descendent pools */
    apr_terminate();
    exit(process_exit_value);
}

/* APR callback invoked if allocation fails. */
static int abort_on_oom(int retcode)
{
    ap_abort_on_oom();
    return retcode; /* unreachable, hopefully. */
}

/* Deregister all hooks when clearing pconf (pre_cleanup).
 * TODO: have a hook to deregister and run them from here?
 *       ap_clear_auth_internal() is already a candidate.
 */
static apr_status_t deregister_all_hooks(void *unused)
{
    (void)unused;
    ap_clear_auth_internal();
    apr_hook_deregister_all();
    return APR_SUCCESS;
}

static void reset_process_pconf(process_rec *process)
{
    if (process->pconf)
    {
        apr_pool_clear(process->pconf);
        ap_server_conf = NULL;
    }
    else
    {
        apr_pool_create(&process->pconf, process->pool);
        apr_pool_tag(process->pconf, "pconf");
    }
    apr_pool_pre_cleanup_register(process->pconf, NULL, deregister_all_hooks);
}

static process_rec *init_process(int *argc, const char *const **argv)
{
    process_rec *process;
    apr_pool_t *cntx;
    apr_status_t stat;
    const char *failed = "apr_app_initialize()";

    stat = apr_app_initialize(argc, argv, NULL);
    if (stat == APR_SUCCESS)
    {
        failed = "apr_pool_create()";
        stat = apr_pool_create(&cntx, NULL);
    }

    if (stat != APR_SUCCESS)
    {
        /* For all intents and purposes, this is impossibly unlikely,
         * but APR doesn't exist yet, we can't use it for reporting
         * these earliest two failures;
         *
         * XXX: Note the apr_ctime() and apr_time_now() calls.  These
         * work, today, against an uninitialized APR, but in the future
         * (if they relied on global pools or mutexes, for example) then
         * the datestamp logic will need to be replaced.
         */
        char ctimebuff[APR_CTIME_LEN];
        apr_ctime(ctimebuff, apr_time_now());
        fprintf(stderr, "[%s] [crit] (%d) %s: %s failed "
                        "to initial context, exiting\n",
                ctimebuff, stat, (*argv)[0], failed);
        apr_terminate();
        exit(1);
    }

    apr_pool_abort_set(abort_on_oom, cntx);
    apr_pool_tag(cntx, "process");
    ap_open_stderr_log(cntx);

    /* Now we have initialized apr and our logger, no more
     * exceptional error reporting required for the lifetime
     * of this server process.
     */

    process = (process_rec *)apr_palloc(cntx, sizeof(process_rec));
    process->pool = cntx;

    process->pconf = NULL;
    reset_process_pconf(process);

    process->argc = *argc;
    process->argv = *argv;
    process->short_name = apr_filepath_name_get((*argv)[0]);

#if AP_HAS_THREAD_LOCAL
    {
        apr_status_t rv;
        apr_thread_t *thd = NULL;
        if ((rv = ap_thread_main_create(&thd, process->pool)))
        {
            char ctimebuff[APR_CTIME_LEN];
            apr_ctime(ctimebuff, apr_time_now());
            fprintf(stderr, "[%s] [crit] (%d) %s: failed "
                            "to initialize thread context, exiting\n",
                    ctimebuff, rv, (*argv)[0]);
            apr_terminate();
            exit(1);
        }
    }
#endif

    return process;
}

void server_main()
{
    // main();
    printf("main()\n");
    int argc;
    const char *const argv[] = {"/usr/local/apache/bin/httpd", "-DDEBUG", "-DONE_PROCESS", "-d", "/usr/local/apache"};
    const char *const *argv_ptr = argv;
    char c;
    int showcompile = 0, showdirectives = 0;
    const char *confname = SERVER_CONFIG_FILE;
    const char *def_server_root = HTTPD_ROOT;
    const char *temp_error_log = NULL;
    const char *error;
    process_rec *process;
    apr_pool_t *pconf;
    apr_pool_t *plog;      /* Pool of log streams, reset _after_ each read of conf */
    apr_pool_t *ptemp;     /* Pool for temporary config stuff, reset often */
    apr_pool_t *pcommands; /* Pool for -D, -C and -c switches */
    apr_getopt_t *opt;
    apr_status_t rv;
    module **mod;
    const char *opt_arg;
    APR_OPTIONAL_FN_TYPE(ap_signal_server) * signal_server;
    int rc = OK;

    AP_MONCONTROL(0); /* turn off profiling of startup */

    process = init_process(&argc, &argv_ptr);
    printf("init_process() success\n");
    ap_pglobal = process->pool;
    pconf = process->pconf;
    ap_server_argv0 = process->short_name;
    ap_init_rng(ap_pglobal);
    /* Set up the OOM callback in the global pool, so all pools should
     * by default inherit it. */
    apr_pool_abort_set(abort_on_oom, apr_pool_parent_get(process->pool));

#if APR_CHARSET_EBCDIC
    if (ap_init_ebcdic(ap_pglobal) != APR_SUCCESS)
    {
        destroy_and_exit_process(process, 1);
    }
#endif

    apr_pool_create(&pcommands, ap_pglobal);
    apr_pool_tag(pcommands, "pcommands");
    ap_server_pre_read_config = apr_array_make(pcommands, 1,
                                               sizeof(const char *));
    ap_server_post_read_config = apr_array_make(pcommands, 1,
                                                sizeof(const char *));
    ap_server_config_defines = apr_array_make(pcommands, 1,
                                              sizeof(const char *));

    error = ap_setup_prelinked_modules(process);
    if (error)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_EMERG, 0, NULL, APLOGNO(00012) "%s: %s", ap_server_argv0, error);
        destroy_and_exit_process(process, 1);
    }
    printf("ap_setup_prelinked_modules() success\n");

    ap_run_rewrite_args(process);
    printf("ap_run_rewrite_args() success\n");

    /* Maintain AP_SERVER_BASEARGS list in http_main.h to allow the MPM
     * to safely pass on our args from its rewrite_args() handler.
     */
    apr_getopt_init(&opt, pcommands, process->argc, process->argv);
    printf("apr_getopt_init() success\n");

    rv = apr_getopt(opt, AP_SERVER_BASEARGS, &c, &opt_arg);
    if (ap_run_mode == AP_SQ_RM_UNKNOWN)
        ap_run_mode = AP_SQ_RM_NORMAL;
    /* bad cmdline option?  then we die */
    if (rv != APR_EOF || opt->ind < opt->argc)
    {
        destroy_and_exit_process(process, 1);
    }
    printf("apr_getopt() success\n");
    ap_main_state = AP_SQ_MS_CREATE_PRE_CONFIG;
    apr_pool_create(&plog, ap_pglobal);
    apr_pool_tag(plog, "plog");
    apr_pool_create(&ptemp, pconf);
    apr_pool_tag(ptemp, "ptemp");

    /* Note that we preflight the config file once
     * before reading it _again_ in the main loop.
     * This allows things, log files configuration
     * for example, to settle down.
     */

    ap_server_root = def_server_root;
    if (temp_error_log)
    {
        ap_replace_stderr_log(process->pool, temp_error_log);
    }
    ap_server_conf = NULL; /* set early by ap_read_config() for logging */
    if (!ap_read_config(process, ptemp, confname, &ap_conftree))
    {
        if (showcompile)
        {
            /* Well, we tried. Show as much as we can, but exit nonzero to
             * indicate that something's not right. The cause should have
             * already been logged. */
            show_compile_settings();
        }
        destroy_and_exit_process(process, 1);
    }
    ap_assert(ap_server_conf != NULL);
    printf("ap_server_conf: %p\n", ap_server_conf);
    printf("ap_read_config() success\n");
    apr_pool_cleanup_register(pconf, &ap_server_conf, ap_pool_cleanup_set_null,
                              apr_pool_cleanup_null);

    if (showcompile)
    { /* deferred due to dynamically loaded MPM */
        show_compile_settings();
        destroy_and_exit_process(process, 0);
    }

    /* sort hooks here to make sure pre_config hooks are sorted properly */
    apr_hook_sort_all();

    if (ap_run_pre_config(pconf, plog, ptemp) != OK)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_ERR, 0,
                     NULL, APLOGNO(00013) "Pre-configuration failed");
        destroy_and_exit_process(process, 1);
    }
    printf("ap_run_pre_config() success\n");

    rv = ap_process_config_tree(ap_server_conf, ap_conftree,
                                process->pconf, ptemp);
    if (rv == OK)
    {
        ap_fixup_virtual_hosts(pconf, ap_server_conf);
        ap_fini_vhost_config(pconf, ap_server_conf);
        /*
         * Sort hooks again because ap_process_config_tree may have add modules
         * and hence hooks. This happens with mod_perl and modules written in
         * perl.
         */
        apr_hook_sort_all();

        if (ap_run_check_config(pconf, plog, ptemp, ap_server_conf) != OK)
        {
            ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_ERR, 0,
                         NULL, APLOGNO(00014) "Configuration check failed");
            destroy_and_exit_process(process, 1);
        }

        if (ap_run_mode != AP_SQ_RM_NORMAL)
        {
            if (showdirectives)
            { /* deferred in case of DSOs */
                ap_show_directives();
                destroy_and_exit_process(process, 0);
            }
            else
            {
                ap_run_test_config(pconf, ap_server_conf);
                if (ap_run_mode == AP_SQ_RM_CONFIG_TEST)
                    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, "Syntax OK");
            }
            destroy_and_exit_process(process, 0);
        }
    }

    /* If our config failed, deal with that here. */
    if (rv != OK)
    {
        destroy_and_exit_process(process, 1);
    }
    printf("ap_process_config_tree() success\n");

    signal_server = APR_RETRIEVE_OPTIONAL_FN(ap_signal_server);
    if (signal_server)
    {
        int exit_status;

        if (signal_server(&exit_status, pconf) != 0)
        {
            destroy_and_exit_process(process, exit_status);
        }
    }
    printf("APR_RETRIEVE_OPTIONAL_FN() success\n");

    apr_pool_clear(plog);

    if (ap_run_open_logs(pconf, plog, ptemp, ap_server_conf) != OK)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_ERR,
                     0, NULL, APLOGNO(00015) "Unable to open logs");
        destroy_and_exit_process(process, 1);
    }
    printf("ap_run_open_logs() success\n");

    if (ap_run_post_config(pconf, plog, ptemp, ap_server_conf) != OK)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_ERR, 0,
                     NULL, APLOGNO(00016) "Configuration Failed");
        destroy_and_exit_process(process, 1);
    }
    printf("ap_run_post_config() success\n");
    printf("ap_server_conf: %p\n", ap_server_conf);

    apr_pool_destroy(ptemp);
    ap_main_state = AP_SQ_MS_DESTROY_CONFIG;
    reset_process_pconf(process);

    ap_main_state = AP_SQ_MS_CREATE_CONFIG;
    ap_config_generation++;
    for (mod = ap_prelinked_modules; *mod != NULL; mod++)
    {
        ap_register_hooks(*mod, pconf);
    }

    /* This is a hack until we finish the code so that it only reads
     * the config file once and just operates on the tree already in
     * memory.  rbb
     */
    ap_conftree = NULL;
    apr_pool_create(&ptemp, pconf);
    apr_pool_tag(ptemp, "ptemp");
    ap_server_root = def_server_root;
    ap_server_conf = NULL; /* set early by ap_read_config() for logging */
    if (!ap_read_config(process, ptemp, confname, &ap_conftree))
    {
        destroy_and_exit_process(process, 1);
    }
    printf("ap_read_config() success\n");
    ap_assert(ap_server_conf != NULL);
    apr_pool_cleanup_register(pconf, &ap_server_conf,
                              ap_pool_cleanup_set_null, apr_pool_cleanup_null);
    /* sort hooks here to make sure pre_config hooks are sorted properly */
    apr_hook_sort_all();

    if (ap_run_pre_config(pconf, plog, ptemp) != OK)
    {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL,
                     APLOGNO(00017) "Pre-configuration failed, exiting");
        destroy_and_exit_process(process, 1);
    }
    printf("ap_run_pre_config() success\n");

    if (ap_process_config_tree(ap_server_conf, ap_conftree, process->pconf,
                               ptemp) != OK)
    {
        destroy_and_exit_process(process, 1);
    }
    printf("ap_process_config_tree() success\n");
    ap_fixup_virtual_hosts(pconf, ap_server_conf);
    ap_fini_vhost_config(pconf, ap_server_conf);
    /*
     * Sort hooks again because ap_process_config_tree may have add modules
     * and hence hooks. This happens with mod_perl and modules written in
     * perl.
     */
    apr_hook_sort_all();

    if (ap_run_check_config(pconf, plog, ptemp, ap_server_conf) != OK)
    {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL,
                     APLOGNO(00018) "Configuration check failed, exiting");
        destroy_and_exit_process(process, 1);
    }
    printf("ap_run_check_config() success\n");

    apr_pool_clear(plog);
    if (ap_run_open_logs(pconf, plog, ptemp, ap_server_conf) != OK)
    {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL,
                     APLOGNO(00019) "Unable to open logs, exiting");
        destroy_and_exit_process(process, 1);
    }
    printf("ap_run_open_logs() success\n");

    if (ap_run_post_config(pconf, plog, ptemp, ap_server_conf) != OK)
    {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL,
                     APLOGNO(00020) "Configuration Failed, exiting");
        destroy_and_exit_process(process, 1);
    }
    printf("ap_run_post_config() success\n");

    apr_pool_destroy(ptemp);

    ap_run_optional_fn_retrieve();

    ap_main_state = AP_SQ_MS_RUN_MPM;
    // rc = ap_run_mpm(pconf, plog, ap_server_conf);
}

conn_rec *create_conn()
{
    server_main();
    printf("ap_run_mpm(pconf, plog, ap_server_conf)\n");

    // ap_run_mpm(pconf, plog, ap_server_conf) -> worker_run at server/main.c:856
    ap_run_pre_mpm(ap_server_conf->process->pool, SB_SHARED);
    // server_main_loop(remaining_children_to_start) at server/mpm/worker/worker.c:1926
    // startup_children(remaining_children_to_start) at server/mpm/worker/worker.c:1831
    // make_child(ap_server_conf, i, i % retained->mpm->num_buckets) at server/mpm/worker/worker.c:1452
    // child_main(slot, 0) at server/mpm/worker/worker.c:1377
    // MEMO: bunch of thread initialization methods called here
    // MEMO: the method below is the one initializing `pruntime`, which is used everywhere
    // setup_threads_runtime();
    apr_pool_create(&pruntime, pconf);

    // ap_thread_create(&start_thread_id, thread_attr, start_threads, ts, pchild) at server/mpm/worker/worker.c:1273
    printf("ap_thread_create(&start_thread_id, thread_attr, start_threads, ts, pchild)\n");
    // start_threads
    proc_info *my_info;
    my_info = (proc_info *)ap_malloc(sizeof(proc_info));
    my_info->pid = 0;
    my_info->tid = 0;
    my_info->sd = 0;
    // ap_thread_create(&threads[i], thread_attr, worker_thread, my_info, pruntime);
    // at server/mpm/event/event.c:2576
    printf("ap_thread_create(&threads[i], thread_attr, worker_thread, my_info, pruntime)\n");
    thread_ctx *ctx = (thread_ctx *)apr_palloc(pruntime, sizeof(*ctx));
    ctx->func = _worker_thread; // worker_thread
    ctx->data = my_info;        // my_info
    // // apr_thread_create(thread, attr, thread_start, ctx, pruntime) at server/util.c:3221
    // printf("apr_thread_create(thread, attr, thread_start, ctx, pruntime)\n");
    // apr_thread_t **new_;
    // (*new_) = (apr_thread_t *)apr_pcalloc(pruntime, sizeof(apr_thread_t));
    // (*new_)->data = ctx;           // ctx
    // (*new_)->func = _thread_start; // thread_start
    // // dummy_worker(*new_) at apr-1.7.4/threadproc/unix/thread.c:179
    // // thread_start(*new_, ctx);
    // // worker_thread(*new_, my_info);
    printf("worker_thread(*new_, my_info)\n");
    proc_info *ti = my_info;
    int process_slot = ti->pid;
    int thread_slot = ti->tid;
    apr_socket_t *csd = NULL;
    apr_bucket_alloc_t *bucket_alloc;
    apr_pool_t *ptrans; /* Pool for per-transaction stuff */
    free(ti);
    apr_pool_create(&ptrans, NULL);
    bucket_alloc = apr_bucket_alloc_create(ptrans);

    // // process_socket(*new_, ptrans, csd, process_slot, thread_slot, bucket_alloc);
    printf("process_socket(*new_, ptrans, csd, process_slot, thread_slot, bucket_alloc)\n");
    conn_rec *current_conn;
    long conn_id = ID_FROM_CHILD_THREAD(process_slot, thread_slot);
    ap_sb_handle_t *sbh;
    ap_create_sb_handle(&sbh, ptrans, process_slot, thread_slot);
    printf("ap_create_sb_handle() success\n");
    // -> core_create_conn
    // current_conn = ap_run_create_connection(ptrans, ap_server_conf, csd,
    //                                         conn_id, sbh, bucket_alloc);
    current_conn = (conn_rec *)apr_pcalloc(ptrans, sizeof(conn_rec));
    current_conn->sbh = sbh;
    current_conn->pool = ptrans;
    current_conn->conn_config = ap_create_conn_config(ptrans);
    current_conn->notes = apr_table_make(ptrans, 5);
    current_conn->base_server = ap_server_conf;
    current_conn->id = conn_id;
    current_conn->bucket_alloc = bucket_alloc;
    current_conn->clogging_input_filters = 0;
    apr_thread_t *dummy_thread;
    current_conn->current_thread = dummy_thread;
    // ap_process_connection(current_conn, csd);
    printf("connection created\n");
    return current_conn;
}

request_rec *create_req()
{
    conn_rec *c = create_conn();
    // // server/connection.c
    // ap_process_connection(current_conn, sock);
    // // modules/http/http_core.c
    // ap_run_process_connection(c); -> ap_process_http_connection(c);
    // ap_process_http_async_connection(c);
    // request_rec *r;

    // r = ap_read_request(c);
    int access_status;
    apr_bucket_brigade *tmp_bb;

    request_rec *r = ap_create_request(c);

    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    c->keepalive = AP_CONN_UNKNOWN;
    // ap_run_pre_read_request(r, c);

    r->unparsed_uri = "/file1.html";
    r->uri = "/file1.html";
    // apr_uri_t parsed_uri = {.path = "/file1.html"};
    // r->parsed_uri = parsed_uri;
    printf("request created\n");
    // conn_state_t *cs = c->cs;
    // ap_update_child_status_from_conn((ap_sb_handle_t *)c->sbh, SERVER_BUSY_READ, c);
    // if (ap_extended_status)
    // {
    //     ap_set_conn_count((ap_sb_handle_t *)c->sbh, r, c->keepalives);
    // }
    // // // server/protocol.c
    // r = ap_read_request(c);
    // cs->state = CONN_STATE_HANDLER;
    // if (ap_extended_status)
    // {
    //     ap_set_conn_count((ap_sb_handle_t *)c->sbh, r, c->keepalives + 1);
    // }
    // ap_update_child_status((ap_sb_handle_t *)c->sbh, SERVER_BUSY_WRITE, r);
    // // modules/http/http_request.c
    // ap_process_async_request(r);
    // // server/request.c
    // ap_process_request_internal(r);
    return r;
}

int main()
{
    request_rec *r = create_req();

    // server_main();
    // request_rec *r;
    int access_status;
    access_status = ap_process_request_internal(r);
    printf("access_status: %d\n", access_status);
    if (access_status == OK)
    {
        access_status = ap_invoke_handler(r);
        printf("HTTP status: %d \n", access_status);
    }
    return 0;
}
