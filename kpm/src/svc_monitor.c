/* svc_monitor.c - KPM v9.0.0
 * ARM64 SVC system-call monitor for Pixel 6 / Android 12 / kernel 5.10.43
 * KernelPatch Module - CTL0 command interface
 *
 * v9.0.0 critical fixes vs v8.3:
 *   1. hook_syscalln() called with correct 5 params (nr, narg, before, after, udata)
 *   2. unhook_syscalln() replaces non-existent unhook_syscall()
 *   3. compat_strncpy_from_user replaces non-existent compat_copy_from_user
 *   4. syscall_args(fargs) used for correct arg extraction (has_syscall_wrapper)
 *   5. SO+offset caller resolution via /proc/<pid>/maps
 *   6. Comprehensive parameter parsing for all monitored syscalls
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <syscall.h>

KPM_NAME("svc_monitor");
KPM_VERSION("9.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SVC Monitor");
KPM_DESCRIPTION("ARM64 SVC syscall monitor with SO+offset resolution");

static void kp_memset(void *dst, int c, unsigned long n)
{
    unsigned long i;
    volatile unsigned char *d = (volatile unsigned char *)dst;
    unsigned char v = (unsigned char)c;
    for (i = 0; i < n; i++) d[i] = v;
}

static void kp_memcpy(void *dst, const void *src, unsigned long n)
{
    unsigned long i;
    volatile unsigned char *d = (volatile unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (i = 0; i < n; i++) d[i] = s[i];
}

/* ================================================================
 * Syscall number definitions (ARM64, kernel 5.10)
 * ================================================================ */
#define __NR_io_setup           0
#define __NR_io_destroy         1
#define __NR_io_submit          2
#define __NR_io_cancel          3
#define __NR_io_getevents       4
#define __NR_setxattr           5
#define __NR_getxattr           8
#define __NR_listxattr          11
#define __NR_removexattr        14
#define __NR_getcwd             17
#define __NR_lookup_dcookie     18
#define __NR_eventfd2           19
#define __NR_epoll_create1      20
#define __NR_epoll_ctl          21
#define __NR_epoll_pwait        22
#define __NR_dup                23
#define __NR_dup3               24
#define __NR_fcntl              25
#define __NR_inotify_init1      26
#define __NR_inotify_add_watch  27
#define __NR_inotify_rm_watch   28
#define __NR_ioctl              29
#define __NR_ioprio_set         30
#define __NR_ioprio_get         31
#define __NR_flock              32
#define __NR_mknodat            33
#define __NR_mkdirat            34
#define __NR_unlinkat           35
#define __NR_symlinkat          36
#define __NR_linkat             37
#define __NR_renameat           38
#define __NR_umount2            39
#define __NR_mount              40
#define __NR_pivot_root         41
#define __NR_nfsservctl         42
#define __NR_statfs             43
#define __NR_fstatfs            44
#define __NR_truncate           45
#define __NR_ftruncate          46
#define __NR_fallocate          47
#define __NR_faccessat          48
#define __NR_chdir              49
#define __NR_fchdir             50
#define __NR_chroot             51
#define __NR_fchmod             52
#define __NR_fchmodat           53
#define __NR_fchownat           54
#define __NR_fchown             55
#define __NR_openat             56
#define __NR_close              57
#define __NR_vhangup            58
#define __NR_pipe2              59
#define __NR_quotactl           60
#define __NR_getdents64         61
#define __NR_lseek              62
#define __NR_read               63
#define __NR_write              64
#define __NR_readv              65
#define __NR_writev             66
#define __NR_pread64            67
#define __NR_pwrite64           68
#define __NR_preadv             69
#define __NR_pwritev            70
#define __NR_sendfile           71
#define __NR_pselect6           72
#define __NR_ppoll              73
#define __NR_signalfd4          74
#define __NR_vmsplice           75
#define __NR_splice             76
#define __NR_tee                77
#define __NR_readlinkat         78
#define __NR_fstatat            79
#define __NR_fstat              80
#define __NR_sync               81
#define __NR_fsync              82
#define __NR_fdatasync          83
#define __NR_sync_file_range    84
#define __NR_timerfd_create     85
#define __NR_timerfd_settime    86
#define __NR_timerfd_gettime    87
#define __NR_utimensat          88
#define __NR_acct               89
#define __NR_capget             90
#define __NR_capset             91
#define __NR_personality        92
#define __NR_exit               93
#define __NR_exit_group         94
#define __NR_waitid             95
#define __NR_set_tid_address    96
#define __NR_unshare            97
#define __NR_futex              98
#define __NR_set_robust_list    99
#define __NR_get_robust_list    100
#define __NR_nanosleep          101
#define __NR_getitimer          102
#define __NR_setitimer          103
#define __NR_kexec_load         104
#define __NR_init_module        105
#define __NR_delete_module      106
#define __NR_timer_create       107
#define __NR_timer_gettime      108
#define __NR_timer_getoverrun   109
#define __NR_timer_settime      110
#define __NR_timer_delete       111
#define __NR_clock_settime      112
#define __NR_clock_gettime      113
#define __NR_clock_getres       114
#define __NR_clock_nanosleep    115
#define __NR_syslog             116
#define __NR_ptrace             117
#define __NR_sched_setparam     118
#define __NR_sched_setscheduler 119
#define __NR_sched_getscheduler 120
#define __NR_sched_getparam     121
#define __NR_sched_setaffinity  122
#define __NR_sched_getaffinity  123
#define __NR_sched_yield        124
#define __NR_sched_get_priority_max 125
#define __NR_sched_get_priority_min 126
#define __NR_sched_rr_get_interval  127
#define __NR_restart_syscall    128
#define __NR_kill               129
#define __NR_tkill              130
#define __NR_tgkill             131
#define __NR_sigaltstack        132
#define __NR_rt_sigsuspend      133
#define __NR_rt_sigaction       134
#define __NR_rt_sigprocmask     135
#define __NR_rt_sigpending      136
#define __NR_rt_sigtimedwait    137
#define __NR_rt_sigqueueinfo    138
#define __NR_rt_sigreturn       139
#define __NR_setpriority        140
#define __NR_getpriority        141
#define __NR_reboot             142
#define __NR_setregid           143
#define __NR_setgid             144
#define __NR_setreuid           145
#define __NR_setuid             146
#define __NR_setresuid          147
#define __NR_getresuid          148
#define __NR_setresgid          149
#define __NR_getresgid          150
#define __NR_setfsuid           151
#define __NR_setfsgid           152
#define __NR_times              153
#define __NR_setpgid            154
#define __NR_getpgid            155
#define __NR_getsid             156
#define __NR_setsid             157
#define __NR_getgroups          158
#define __NR_setgroups          159
#define __NR_uname              160
#define __NR_sethostname        161
#define __NR_setdomainname      162
#define __NR_getrlimit          163
#define __NR_setrlimit          164
#define __NR_getrusage          165
#define __NR_umask              166
#define __NR_prctl              167
#define __NR_getcpu             168
#define __NR_gettimeofday       169
#define __NR_settimeofday       170
#define __NR_adjtimex           171
#define __NR_getpid             172
#define __NR_getppid            173
#define __NR_getuid             174
#define __NR_geteuid            175
#define __NR_getgid             176
#define __NR_getegid            177
#define __NR_gettid             178
#define __NR_sysinfo            179
#define __NR_mq_open            180
#define __NR_mq_unlink          181
#define __NR_mq_timedsend       182
#define __NR_mq_timedreceive    183
#define __NR_mq_notify          184
#define __NR_mq_getsetattr      185
#define __NR_msgget             186
#define __NR_msgctl             187
#define __NR_msgrcv             188
#define __NR_msgsnd             189
#define __NR_semget             190
#define __NR_semctl             191
#define __NR_semtimedop         192
#define __NR_semop              193
#define __NR_shmget             194
#define __NR_shmctl             195
#define __NR_shmat              196
#define __NR_shmdt              197
#define __NR_socket             198
#define __NR_socketpair         199
#define __NR_bind               200
#define __NR_listen             201
#define __NR_accept             202
#define __NR_connect            203
#define __NR_getsockname        204
#define __NR_getpeername        205
#define __NR_sendto             206
#define __NR_recvfrom           207
#define __NR_setsockopt         208
#define __NR_getsockopt         209
#define __NR_shutdown           210
#define __NR_sendmsg            211
#define __NR_recvmsg            212
#define __NR_readahead          213
#define __NR_brk                214
#define __NR_munmap             215
#define __NR_mremap             216
#define __NR_add_key            217
#define __NR_request_key        218
#define __NR_keyctl             219
#define __NR_clone              220
#define __NR_execve             221
#define __NR_mmap               222
#define __NR_fadvise64          223
#define __NR_swapon             224
#define __NR_swapoff            225
#define __NR_mprotect           226
#define __NR_msync              227
#define __NR_mlock              228
#define __NR_munlock            229
#define __NR_mlockall           230
#define __NR_munlockall         231
#define __NR_mincore            232
#define __NR_madvise            233
#define __NR_remap_file_pages   234
#define __NR_mbind              235
#define __NR_get_mempolicy      236
#define __NR_set_mempolicy      237
#define __NR_migrate_pages      238
#define __NR_move_pages         239
#define __NR_rt_tgsigqueueinfo  240
#define __NR_perf_event_open    241
#define __NR_accept4            242
#define __NR_recvmmsg           243
#define __NR_wait4              260
#define __NR_prlimit64          261
#define __NR_fanotify_init      262
#define __NR_fanotify_mark      263
#define __NR_name_to_handle_at  264
#define __NR_open_by_handle_at  265
#define __NR_clock_adjtime      266
#define __NR_syncfs             267
#define __NR_setns              268
#define __NR_sendmmsg           269
#define __NR_process_vm_readv   270
#define __NR_process_vm_writev  271
#define __NR_kcmp               272
#define __NR_finit_module       273
#define __NR_sched_setattr      274
#define __NR_sched_getattr      275
#define __NR_renameat2          276
#define __NR_seccomp            277
#define __NR_getrandom          278
#define __NR_memfd_create       279
#define __NR_bpf                280
#define __NR_execveat           281
#define __NR_userfaultfd        282
#define __NR_membarrier         283
#define __NR_mlock2             284
#define __NR_copy_file_range    285
#define __NR_preadv2            286
#define __NR_pwritev2           287
#define __NR_pkey_mprotect      288
#define __NR_pkey_alloc         289
#define __NR_pkey_free          290
#define __NR_statx              291
#define __NR_io_pgetevents      292
#define __NR_rseq               293
#define __NR_kexec_file_load    294
#define __NR_pidfd_send_signal  424
#define __NR_io_uring_setup     425
#define __NR_io_uring_enter     426
#define __NR_io_uring_register  427
#define __NR_open_tree          428
#define __NR_move_mount         429
#define __NR_fsopen             430
#define __NR_fsconfig           431
#define __NR_fsmount            432
#define __NR_fspick             433
#define __NR_pidfd_open         434
#define __NR_clone3             435
#define __NR_close_range        436
#define __NR_openat2            437
#define __NR_pidfd_getfd        438
#define __NR_faccessat2         439

/* ================================================================
 * Data structures and configuration
 * ================================================================ */

#define MAX_EVENTS          1024
#define MAX_HOOKS           128
#define MAX_PATH_LEN        256
#define MAX_ARG_STR         128
#define MAX_COMM_LEN        16
#define OUTPUT_BUF_SIZE     (128 * 1024)
#define MAPS_CACHE_SIZE     64
#define MAPS_LINE_BUF       512

/* Event structure */
struct svc_event {
    unsigned long long timestamp;
    unsigned int seq;
    int nr;
    int pid;
    int tid;
    unsigned int uid;
    char comm[MAX_COMM_LEN];
    unsigned long long args[6];
    char arg_detail[512];
    unsigned long long caller_pc;
    unsigned long long caller_lr;
    char caller_so[MAX_PATH_LEN];
    unsigned long long caller_offset;
};

/* Maps cache entry for SO resolution */
struct maps_entry {
    unsigned long long vm_start;
    unsigned long long vm_end;
    unsigned long long pgoff;
    char name[MAX_PATH_LEN];
};

struct pid_maps {
    int pid;
    int count;
    unsigned long long update_time;
    struct maps_entry entries[MAPS_CACHE_SIZE];
};

/* ================================================================
 * Globals
 * ================================================================ */

static int g_running = 0;
static int g_initialized = 0;
static unsigned int g_seq = 0;

/* Event ring buffer */
static struct svc_event g_events[MAX_EVENTS];
static int g_ev_head = 0;
static int g_ev_tail = 0;
static int g_ev_count = 0;
static int g_ev_dropped = 0;

/* Hook tracking */
static int g_hooked_nrs[MAX_HOOKS];
static int g_hook_count = 0;

/* Target filter */
static int g_target_pid = 0;
static unsigned int g_target_uid = 0;
static char g_target_comm[MAX_COMM_LEN] = {0};

/* Monitored syscall bitmap */
#define BITMAP_SIZE 16
static unsigned long g_bitmap[BITMAP_SIZE] = {0};

/* Maps cache for SO resolution (single-target) */
static struct pid_maps g_maps_cache = {0};

/* Output buffer */
static char g_outbuf[OUTPUT_BUF_SIZE];
static int g_outpos = 0;

/* Re-entrancy guard */
static int g_in_hook = 0;


/* ================================================================
 * Syscall name table
 * ================================================================ */

struct nr_name { int nr; const char *name; };
static const struct nr_name g_syscall_names[] = {
    {0,"io_setup"},{1,"io_destroy"},{2,"io_submit"},{3,"io_cancel"},
    {4,"io_getevents"},{5,"setxattr"},{8,"getxattr"},{11,"listxattr"},
    {14,"removexattr"},{17,"getcwd"},{19,"eventfd2"},{20,"epoll_create1"},
    {21,"epoll_ctl"},{22,"epoll_pwait"},{23,"dup"},{24,"dup3"},
    {25,"fcntl"},{26,"inotify_init1"},{27,"inotify_add_watch"},
    {28,"inotify_rm_watch"},{29,"ioctl"},{30,"ioprio_set"},{31,"ioprio_get"},
    {32,"flock"},{33,"mknodat"},{34,"mkdirat"},{35,"unlinkat"},
    {36,"symlinkat"},{37,"linkat"},{38,"renameat"},{39,"umount2"},
    {40,"mount"},{43,"statfs"},{44,"fstatfs"},{45,"truncate"},
    {46,"ftruncate"},{47,"fallocate"},{48,"faccessat"},{49,"chdir"},
    {50,"fchdir"},{51,"chroot"},{52,"fchmod"},{53,"fchmodat"},
    {54,"fchownat"},{55,"fchown"},{56,"openat"},{57,"close"},
    {59,"pipe2"},{61,"getdents64"},{62,"lseek"},{63,"read"},
    {64,"write"},{65,"readv"},{66,"writev"},{67,"pread64"},
    {68,"pwrite64"},{71,"sendfile"},{72,"pselect6"},{73,"ppoll"},
    {76,"splice"},{78,"readlinkat"},{79,"fstatat"},{80,"fstat"},
    {81,"sync"},{82,"fsync"},{83,"fdatasync"},{85,"timerfd_create"},
    {88,"utimensat"},{89,"acct"},{90,"capget"},{91,"capset"},
    {93,"exit"},{94,"exit_group"},{95,"waitid"},{96,"set_tid_address"},
    {97,"unshare"},{98,"futex"},{99,"set_robust_list"},
    {100,"get_robust_list"},{101,"nanosleep"},{103,"setitimer"},
    {104,"kexec_load"},{105,"init_module"},{106,"delete_module"},
    {113,"clock_gettime"},{114,"clock_getres"},{115,"clock_nanosleep"},
    {116,"syslog"},{117,"ptrace"},{124,"sched_yield"},
    {129,"kill"},{130,"tkill"},{131,"tgkill"},{132,"sigaltstack"},
    {134,"rt_sigaction"},{135,"rt_sigprocmask"},{140,"setpriority"},
    {141,"getpriority"},{142,"reboot"},{146,"setuid"},{147,"setresuid"},
    {153,"times"},{154,"setpgid"},{157,"setsid"},{160,"uname"},
    {163,"getrlimit"},{164,"setrlimit"},{166,"umask"},{167,"prctl"},
    {168,"getcpu"},{169,"gettimeofday"},{172,"getpid"},{173,"getppid"},
    {174,"getuid"},{175,"geteuid"},{176,"getgid"},{177,"getegid"},
    {178,"gettid"},{179,"sysinfo"},
    {186,"msgget"},{187,"msgctl"},{188,"msgrcv"},{189,"msgsnd"},
    {190,"semget"},{191,"semctl"},{194,"shmget"},{195,"shmctl"},
    {196,"shmat"},{197,"shmdt"},
    {198,"socket"},{199,"socketpair"},{200,"bind"},{201,"listen"},
    {202,"accept"},{203,"connect"},{204,"getsockname"},{205,"getpeername"},
    {206,"sendto"},{207,"recvfrom"},{208,"setsockopt"},{209,"getsockopt"},
    {210,"shutdown"},{211,"sendmsg"},{212,"recvmsg"},
    {214,"brk"},{215,"munmap"},{216,"mremap"},
    {220,"clone"},{221,"execve"},{222,"mmap"},{223,"fadvise64"},
    {226,"mprotect"},{227,"msync"},{228,"mlock"},{229,"munlock"},
    {233,"madvise"},
    {240,"rt_tgsigqueueinfo"},{241,"perf_event_open"},{242,"accept4"},
    {260,"wait4"},{261,"prlimit64"},{268,"setns"},{269,"sendmmsg"},
    {270,"process_vm_readv"},{271,"process_vm_writev"},{272,"kcmp"},
    {273,"finit_module"},{276,"renameat2"},{277,"seccomp"},
    {278,"getrandom"},{279,"memfd_create"},{280,"bpf"},{281,"execveat"},
    {284,"mlock2"},{285,"copy_file_range"},{291,"statx"},
    {424,"pidfd_send_signal"},{425,"io_uring_setup"},{426,"io_uring_enter"},
    {427,"io_uring_register"},{434,"pidfd_open"},{435,"clone3"},
    {436,"close_range"},{437,"openat2"},{438,"pidfd_getfd"},
    {439,"faccessat2"},
    {-1, 0}
};

static const char *get_syscall_name(int nr)
{
    const struct nr_name *p = g_syscall_names;
    while (p->nr >= 0) {
        if (p->nr == nr) return p->name;
        p++;
    }
    return "unknown";
}

/* ================================================================
 * Bitmap operations
 * ================================================================ */

static void bitmap_set(int nr)
{
    if (nr < 0 || nr >= BITMAP_SIZE * 64) return;
    g_bitmap[nr / 64] |= (1UL << (nr % 64));
}

static void bitmap_clear(int nr)
{
    if (nr < 0 || nr >= BITMAP_SIZE * 64) return;
    g_bitmap[nr / 64] &= ~(1UL << (nr % 64));
}

static int bitmap_test(int nr)
{
    if (nr < 0 || nr >= BITMAP_SIZE * 64) return 0;
    return (g_bitmap[nr / 64] >> (nr % 64)) & 1;
}

static void bitmap_clear_all(void)
{
    kp_memset(g_bitmap, 0, sizeof(g_bitmap));
}

/* ================================================================
 * Safe user-space reading (v9 fix: use compat_strncpy_from_user)
 * ================================================================ */

static long safe_strncpy_user(char *dst, unsigned long user_addr, long maxlen)
{
    long ret;
    if (!user_addr || maxlen <= 0) {
        if (maxlen > 0) dst[0] = '\0';
        return 0;
    }
    ret = compat_strncpy_from_user(dst, (const char __user *)user_addr, maxlen);
    if (ret < 0) {
        dst[0] = '\0';
        return 0;
    }
    if (ret >= maxlen)
        dst[maxlen - 1] = '\0';
    return ret;
}

/* ================================================================
 * Process info helpers (using raw_syscall for safety)
 * ================================================================ */

static int get_current_pid(void)
{
    return (int)raw_syscall0(__NR_getpid);
}

static int get_current_tid(void)
{
    return (int)raw_syscall0(__NR_gettid);
}

static unsigned int get_current_uid(void)
{
    return current_uid();
}

/* Read comm from /proc/self/comm via task struct offset */
#define TASK_COMM_OFFSET 2560

static void get_current_comm(char *buf, int size)
{
    unsigned long current_task;
    int i, valid;

    __asm__ volatile("mrs %0, sp_el0" : "=r"(current_task));
    if (!current_task) {
        buf[0] = '?'; buf[1] = '\0';
        return;
    }

    kp_memcpy(buf, (void *)(current_task + TASK_COMM_OFFSET),
              size < MAX_COMM_LEN ? size : MAX_COMM_LEN);
    buf[size - 1] = '\0';

    /* Validate ASCII */
    valid = 1;
    for (i = 0; i < size && buf[i]; i++) {
        if (buf[i] < 0x20 || buf[i] > 0x7e) { valid = 0; break; }
    }
    if (!valid || buf[0] == '\0') {
        buf[0] = '?'; buf[1] = '\0';
    }
}

/* ================================================================
 * JSON escape
 * ================================================================ */

static void json_escape(const char *src, char *dst, int dstsize)
{
    int si = 0, di = 0;
    while (src[si] && di < dstsize - 2) {
        char c = src[si++];
        if (c == '"' || c == '\\') {
            if (di + 2 >= dstsize) break;
            dst[di++] = '\\';
            dst[di++] = c;
        } else if (c == '\n') {
            if (di + 2 >= dstsize) break;
            dst[di++] = '\\';
            dst[di++] = 'n';
        } else if (c == '\t') {
            if (di + 2 >= dstsize) break;
            dst[di++] = '\\';
            dst[di++] = 't';
        } else if (c >= 0x20 && c < 0x7f) {
            dst[di++] = c;
        } else {
            dst[di++] = '.';
        }
    }
    dst[di] = '\0';
}

/* ================================================================
 * Caller resolution: SO + offset via /proc/<pid>/maps
 * ================================================================ */

static void refresh_maps_for_pid(int pid)
{
    char path_buf[64];
    char line_buf[MAPS_LINE_BUF];
    int fd, n, pos, line_start, entry_idx;
    unsigned long long seg_start, seg_end, seg_off;
    char perms[8];

    if (g_maps_cache.pid == pid && g_maps_cache.count > 0)
        return; /* already cached */

    g_maps_cache.pid = pid;
    g_maps_cache.count = 0;

    /* Build path: /proc/<pid>/maps */
    {
        int p = 0, tmp, digits, d;
        const char *prefix = "/proc/";
        const char *suffix = "/maps";
        for (d = 0; prefix[d]; d++) path_buf[p++] = prefix[d];
        /* Convert pid to string */
        if (pid == 0) { path_buf[p++] = '0'; }
        else {
            char num[12]; digits = 0; tmp = pid;
            while (tmp > 0) { num[digits++] = '0' + (tmp % 10); tmp /= 10; }
            for (d = digits - 1; d >= 0; d--) path_buf[p++] = num[d];
        }
        for (d = 0; suffix[d]; d++) path_buf[p++] = suffix[d];
        path_buf[p] = '\0';
    }

    /* Open maps file via raw_syscall */
    fd = (int)raw_syscall3(__NR_openat, -100 /* AT_FDCWD */, (long)path_buf, 0 /* O_RDONLY */);
    if (fd < 0) return;

    entry_idx = 0;
    pos = 0;
    line_start = 0;

    while (entry_idx < MAPS_CACHE_SIZE) {
        n = (int)raw_syscall3(__NR_read, fd, (long)(line_buf + pos), MAPS_LINE_BUF - pos - 1);
        if (n <= 0) break;
        pos += n;
        line_buf[pos] = '\0';

        /* Parse complete lines */
        {
            int i;
            for (i = line_start; i < pos; i++) {
                if (line_buf[i] != '\n') continue;
                line_buf[i] = '\0';

                /* Parse: start-end perms offset ... pathname */
                {
                    const char *lp = &line_buf[line_start];
                    int ci = 0, fi = 0;
                    unsigned long long val;
                    char c;

                    /* Parse start address (hex) */
                    val = 0;
                    while ((c = lp[ci]) && c != '-') {
                        val <<= 4;
                        if (c >= '0' && c <= '9') val |= (c - '0');
                        else if (c >= 'a' && c <= 'f') val |= (c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') val |= (c - 'A' + 10);
                        ci++;
                    }
                    seg_start = val;
                    if (lp[ci] == '-') ci++;

                    /* Parse end address (hex) */
                    val = 0;
                    while ((c = lp[ci]) && c != ' ') {
                        val <<= 4;
                        if (c >= '0' && c <= '9') val |= (c - '0');
                        else if (c >= 'a' && c <= 'f') val |= (c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') val |= (c - 'A' + 10);
                        ci++;
                    }
                    seg_end = val;
                    if (lp[ci] == ' ') ci++;

                    /* Perms (4 chars) */
                    fi = 0;
                    while ((c = lp[ci]) && c != ' ' && fi < 7) { perms[fi++] = c; ci++; }
                    perms[fi] = '\0';
                    if (lp[ci] == ' ') ci++;

                    /* Parse offset (hex) */
                    val = 0;
                    while ((c = lp[ci]) && c != ' ') {
                        val <<= 4;
                        if (c >= '0' && c <= '9') val |= (c - '0');
                        else if (c >= 'a' && c <= 'f') val |= (c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') val |= (c - 'A' + 10);
                        ci++;
                    }
                    seg_off = val;
                    if (lp[ci] == ' ') ci++;

                    /* Skip dev and inode fields */
                    while (lp[ci] && lp[ci] != ' ') ci++; /* dev */
                    if (lp[ci] == ' ') ci++;
                    while (lp[ci] && lp[ci] != ' ') ci++; /* inode */
                    while (lp[ci] == ' ') ci++;

                    /* Remaining = pathname */
                    if (lp[ci] && lp[ci] != '\n' && perms[2] == 'x') {
                        struct maps_entry *me = &g_maps_cache.entries[entry_idx];
                        me->vm_start = seg_start;
                        me->vm_end = seg_end;
                        me->pgoff = seg_off;
                        {
                            int ni = 0;
                            /* Extract basename */
                            const char *np = &lp[ci];
                            const char *last_slash = np;
                            const char *sp;
                            for (sp = np; *sp; sp++) {
                                if (*sp == '/') last_slash = sp + 1;
                            }
                            for (sp = last_slash; *sp && ni < MAX_PATH_LEN - 1; sp++)
                                me->name[ni++] = *sp;
                            me->name[ni] = '\0';
                        }
                        entry_idx++;
                    }
                }

                line_start = i + 1;
            }
        }

        /* Move remaining partial line to beginning */
        if (line_start > 0 && line_start < pos) {
            int rem = pos - line_start;
            int m;
            for (m = 0; m < rem; m++) line_buf[m] = line_buf[line_start + m];
            pos = rem;
            line_start = 0;
        } else if (line_start >= pos) {
            pos = 0;
            line_start = 0;
        }
    }

    raw_syscall1(__NR_close, fd);
    g_maps_cache.count = entry_idx;
}

static void resolve_caller(struct svc_event *ev)
{
    int i;
    unsigned long long pc = ev->caller_pc;

    ev->caller_so[0] = '\0';
    ev->caller_offset = 0;

    if (!pc) return;

    /* Refresh maps cache if needed */
    refresh_maps_for_pid(ev->pid);

    for (i = 0; i < g_maps_cache.count; i++) {
        struct maps_entry *me = &g_maps_cache.entries[i];
        if (pc >= me->vm_start && pc < me->vm_end) {
            kp_memcpy(ev->caller_so, me->name, MAX_PATH_LEN);
            ev->caller_offset = pc - me->vm_start + me->pgoff;
            return;
        }
    }

    /* If not found, use raw hex */
    {
        const char *hex = "0123456789abcdef";
        char *p = ev->caller_so;
        int si;
        p[0] = '0'; p[1] = 'x';
        for (si = 0; si < 16; si++)
            p[2 + si] = hex[(pc >> (60 - si * 4)) & 0xf];
        p[18] = '\0';
    }
}

/* ================================================================
 * Capture caller PC/LR from pt_regs (has_syscall_wrapper aware)
 * ================================================================ */

static void capture_caller(struct svc_event *ev, void *fargs_raw)
{
    ev->caller_pc = 0;
    ev->caller_lr = 0;

    if (has_syscall_wrapper) {
        /* When has_syscall_wrapper=1, arg0 of the hook is pt_regs* */
        unsigned long long *regs;
        hook_fargs6_t *fa = (hook_fargs6_t *)fargs_raw;
        regs = (unsigned long long *)fa->arg0;
        if (regs) {
            ev->caller_pc = regs[32]; /* pc in ARM64 pt_regs is at index 32 */
            ev->caller_lr = regs[30]; /* x30 = LR */
        }
    } else {
        /* Fallback: read SP_EL0 based pt_regs */
        unsigned long long sp;
        __asm__ volatile("mrs %0, sp_el0" : "=r"(sp));
        if (sp) {
            /* pt_regs at top of kernel stack */
            unsigned long long *stack_regs = (unsigned long long *)(sp + 0x40);
            ev->caller_pc = stack_regs[32];
            ev->caller_lr = stack_regs[30];
        }
    }

    /* Strip PAC bits for ARMv8.3+ */
    ev->caller_pc &= 0x0000FFFFFFFFFFFFULL;
    ev->caller_lr &= 0x0000FFFFFFFFFFFFULL;
}

/* ================================================================
 * Event ring buffer
 * ================================================================ */

static void push_event(struct svc_event *ev)
{
    if (g_ev_count >= MAX_EVENTS) {
        g_ev_dropped++;
        return;
    }
    kp_memcpy(&g_events[g_ev_tail], ev, sizeof(*ev));
    g_ev_tail = (g_ev_tail + 1) % MAX_EVENTS;
    g_ev_count++;
}

static int pop_event(struct svc_event *out)
{
    if (g_ev_count <= 0) return 0;
    kp_memcpy(out, &g_events[g_ev_head], sizeof(*out));
    g_ev_head = (g_ev_head + 1) % MAX_EVENTS;
    g_ev_count--;
    return 1;
}

static unsigned long long get_timestamp_ns(void)
{
    /* Use clock_gettime via raw_syscall */
    struct { long tv_sec; long tv_nsec; } ts;
    ts.tv_sec = 0; ts.tv_nsec = 0;
    raw_syscall2(__NR_clock_gettime, 1 /* CLOCK_MONOTONIC */, (long)&ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

/* ================================================================
 * Deep argument parsing - comprehensive syscall parameter decode
 * ================================================================ */

static void deep_parse_args(int nr, unsigned long long *a, char *buf, int bufsize)
{
    char tmp[MAX_ARG_STR];
    char tmp2[MAX_ARG_STR];
    int pos = 0;

    buf[0] = '\0';

#define APPEND(...) do { \
    int _r = __builtin_snprintf(buf + pos, bufsize - pos, __VA_ARGS__); \
    if (_r > 0) pos += _r; \
} while(0)

#define READ_STR(dst, uaddr) safe_strncpy_user(dst, (unsigned long)(uaddr), sizeof(dst))

    switch (nr) {

    /* === File operations === */
    case __NR_openat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",flags=0x%x,mode=0%o",
               (int)a[0], tmp2, (unsigned int)a[2], (unsigned int)a[3]);
        break;
    case __NR_openat2:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",how=%p,size=%lu",
               (int)a[0], tmp2, (void*)a[2], (unsigned long)a[3]);
        break;
    case __NR_close:
        APPEND("fd=%d", (int)a[0]);
        break;
    case __NR_close_range:
        APPEND("fd_lo=%u,fd_hi=%u,flags=0x%x",
               (unsigned int)a[0], (unsigned int)a[1], (unsigned int)a[2]);
        break;
    case __NR_read:
        APPEND("fd=%d,buf=%p,count=%lu", (int)a[0], (void*)a[1], (unsigned long)a[2]);
        break;
    case __NR_write:
        APPEND("fd=%d,buf=%p,count=%lu", (int)a[0], (void*)a[1], (unsigned long)a[2]);
        break;
    case __NR_pread64:
        APPEND("fd=%d,buf=%p,count=%lu,offset=%lld",
               (int)a[0], (void*)a[1], (unsigned long)a[2], (long long)a[3]);
        break;
    case __NR_pwrite64:
        APPEND("fd=%d,buf=%p,count=%lu,offset=%lld",
               (int)a[0], (void*)a[1], (unsigned long)a[2], (long long)a[3]);
        break;
    case __NR_readv:
    case __NR_writev:
        APPEND("fd=%d,iov=%p,iovcnt=%d", (int)a[0], (void*)a[1], (int)a[2]);
        break;
    case __NR_lseek:
        APPEND("fd=%d,offset=%lld,whence=%d", (int)a[0], (long long)a[1], (int)a[2]);
        break;
    case __NR_dup:
        APPEND("oldfd=%d", (int)a[0]);
        break;
    case __NR_dup3:
        APPEND("oldfd=%d,newfd=%d,flags=0x%x", (int)a[0], (int)a[1], (unsigned int)a[2]);
        break;
    case __NR_fcntl:
        APPEND("fd=%d,cmd=%d,arg=0x%lx", (int)a[0], (int)a[1], (unsigned long)a[2]);
        break;
    case __NR_ioctl:
        APPEND("fd=%d,cmd=0x%lx,arg=0x%lx", (int)a[0], (unsigned long)a[1], (unsigned long)a[2]);
        break;
    case __NR_fstat:
        APPEND("fd=%d,statbuf=%p", (int)a[0], (void*)a[1]);
        break;
    case __NR_fstatat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",statbuf=%p,flags=0x%x",
               (int)a[0], tmp2, (void*)a[2], (unsigned int)a[3]);
        break;
    case __NR_statx:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",flags=0x%x,mask=0x%x,statxbuf=%p",
               (int)a[0], tmp2, (unsigned int)a[2], (unsigned int)a[3], (void*)a[4]);
        break;
    case __NR_statfs:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("path=\"%s\",buf=%p", tmp2, (void*)a[1]);
        break;
    case __NR_fstatfs:
        APPEND("fd=%d,buf=%p", (int)a[0], (void*)a[1]);
        break;
    case __NR_getcwd:
        APPEND("buf=%p,size=%lu", (void*)a[0], (unsigned long)a[1]);
        break;
    case __NR_getdents64:
        APPEND("fd=%d,dirent=%p,count=%u", (int)a[0], (void*)a[1], (unsigned int)a[2]);
        break;
    case __NR_sendfile:
        APPEND("out_fd=%d,in_fd=%d,offset=%p,count=%lu",
               (int)a[0], (int)a[1], (void*)a[2], (unsigned long)a[3]);
        break;
    case __NR_copy_file_range:
        APPEND("fd_in=%d,off_in=%p,fd_out=%d,off_out=%p,len=%lu,flags=0x%x",
               (int)a[0], (void*)a[1], (int)a[2], (void*)a[3], (unsigned long)a[4], (unsigned int)a[5]);
        break;

    /* === Path operations === */
    case __NR_faccessat:
    case __NR_faccessat2:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",mode=0%o,flags=0x%x",
               (int)a[0], tmp2, (unsigned int)a[2], (unsigned int)a[3]);
        break;
    case __NR_mkdirat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",mode=0%o", (int)a[0], tmp2, (unsigned int)a[2]);
        break;
    case __NR_mknodat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",mode=0%o,dev=0x%lx",
               (int)a[0], tmp2, (unsigned int)a[2], (unsigned long)a[3]);
        break;
    case __NR_unlinkat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",flags=0x%x", (int)a[0], tmp2, (unsigned int)a[2]);
        break;
    case __NR_renameat:
    case __NR_renameat2:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        {
            char old_esc[MAX_ARG_STR];
            kp_memcpy(old_esc, tmp2, sizeof(old_esc));
            READ_STR(tmp, a[3]);
            json_escape(tmp, tmp2, sizeof(tmp2));
            APPEND("olddirfd=%d,oldpath=\"%s\",newdirfd=%d,newpath=\"%s\"",
                   (int)a[0], old_esc, (int)a[2], tmp2);
        }
        break;
    case __NR_symlinkat:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        {
            char target_esc[MAX_ARG_STR];
            kp_memcpy(target_esc, tmp2, sizeof(target_esc));
            READ_STR(tmp, a[2]);
            json_escape(tmp, tmp2, sizeof(tmp2));
            APPEND("target=\"%s\",newdirfd=%d,linkpath=\"%s\"",
                   target_esc, (int)a[1], tmp2);
        }
        break;
    case __NR_linkat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        {
            char old_esc[MAX_ARG_STR];
            kp_memcpy(old_esc, tmp2, sizeof(old_esc));
            READ_STR(tmp, a[3]);
            json_escape(tmp, tmp2, sizeof(tmp2));
            APPEND("olddirfd=%d,oldpath=\"%s\",newdirfd=%d,newpath=\"%s\",flags=0x%x",
                   (int)a[0], old_esc, (int)a[2], tmp2, (unsigned int)a[4]);
        }
        break;
    case __NR_readlinkat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",buf=%p,bufsiz=%lu",
               (int)a[0], tmp2, (void*)a[2], (unsigned long)a[3]);
        break;
    case __NR_chdir:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("path=\"%s\"", tmp2);
        break;
    case __NR_chroot:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("path=\"%s\"", tmp2);
        break;
    case __NR_fchdir:
        APPEND("fd=%d", (int)a[0]);
        break;
    case __NR_fchmod:
        APPEND("fd=%d,mode=0%o", (int)a[0], (unsigned int)a[1]);
        break;
    case __NR_fchmodat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",mode=0%o", (int)a[0], tmp2, (unsigned int)a[2]);
        break;
    case __NR_fchownat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",uid=%d,gid=%d,flags=0x%x",
               (int)a[0], tmp2, (int)a[2], (int)a[3], (unsigned int)a[4]);
        break;
    case __NR_fchown:
        APPEND("fd=%d,uid=%d,gid=%d", (int)a[0], (int)a[1], (int)a[2]);
        break;
    case __NR_truncate:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("path=\"%s\",length=%lld", tmp2, (long long)a[1]);
        break;
    case __NR_ftruncate:
        APPEND("fd=%d,length=%lld", (int)a[0], (long long)a[1]);
        break;
    case __NR_fallocate:
        APPEND("fd=%d,mode=%d,offset=%lld,len=%lld",
               (int)a[0], (int)a[1], (long long)a[2], (long long)a[3]);
        break;
    case __NR_utimensat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",times=%p,flags=0x%x",
               (int)a[0], tmp2, (void*)a[2], (unsigned int)a[3]);
        break;

    /* === Process operations === */
    case __NR_execve:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("filename=\"%s\",argv=%p,envp=%p", tmp2, (void*)a[1], (void*)a[2]);
        break;
    case __NR_execveat:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("dirfd=%d,path=\"%s\",argv=%p,envp=%p,flags=0x%x",
               (int)a[0], tmp2, (void*)a[2], (void*)a[3], (unsigned int)a[4]);
        break;
    case __NR_clone:
        APPEND("flags=0x%lx,stack=%p,parent_tid=%p,tls=%p,child_tid=%p",
               (unsigned long)a[0], (void*)a[1], (void*)a[2], (void*)a[3], (void*)a[4]);
        break;
    case __NR_clone3:
        APPEND("clone_args=%p,size=%lu", (void*)a[0], (unsigned long)a[1]);
        break;
    case __NR_exit:
    case __NR_exit_group:
        APPEND("status=%d", (int)a[0]);
        break;
    case __NR_wait4:
        APPEND("pid=%d,wstatus=%p,options=0x%x,rusage=%p",
               (int)a[0], (void*)a[1], (unsigned int)a[2], (void*)a[3]);
        break;
    case __NR_waitid:
        APPEND("which=%d,pid=%d,infop=%p,options=0x%x,rusage=%p",
               (int)a[0], (int)a[1], (void*)a[2], (unsigned int)a[3], (void*)a[4]);
        break;
    case __NR_getpid:
    case __NR_getppid:
    case __NR_gettid:
    case __NR_getuid:
    case __NR_geteuid:
    case __NR_getgid:
    case __NR_getegid:
    case __NR_setsid:
    case __NR_sched_yield:
    case __NR_sync:
    case __NR_vhangup:
        APPEND("(no args)");
        break;
    case __NR_setuid:
        APPEND("uid=%d", (int)a[0]);
        break;
    case __NR_setresuid:
        APPEND("ruid=%d,euid=%d,suid=%d", (int)a[0], (int)a[1], (int)a[2]);
        break;
    case __NR_setpgid:
        APPEND("pid=%d,pgid=%d", (int)a[0], (int)a[1]);
        break;
    case __NR_getpgid:
        APPEND("pid=%d", (int)a[0]);
        break;
    case __NR_prctl:
        APPEND("option=%d,arg2=0x%lx,arg3=0x%lx,arg4=0x%lx,arg5=0x%lx",
               (int)a[0], (unsigned long)a[1], (unsigned long)a[2],
               (unsigned long)a[3], (unsigned long)a[4]);
        break;
    case __NR_ptrace:
        APPEND("request=%ld,pid=%d,addr=0x%lx,data=0x%lx",
               (long)a[0], (int)a[1], (unsigned long)a[2], (unsigned long)a[3]);
        break;
    case __NR_set_tid_address:
        APPEND("tidptr=%p", (void*)a[0]);
        break;
    case __NR_unshare:
        APPEND("flags=0x%lx", (unsigned long)a[0]);
        break;
    case __NR_prlimit64:
        APPEND("pid=%d,resource=%d,new_rlim=%p,old_rlim=%p",
               (int)a[0], (int)a[1], (void*)a[2], (void*)a[3]);
        break;
    case __NR_getrlimit:
        APPEND("resource=%d,rlim=%p", (int)a[0], (void*)a[1]);
        break;
    case __NR_setrlimit:
        APPEND("resource=%d,rlim=%p", (int)a[0], (void*)a[1]);
        break;
    case __NR_personality:
        APPEND("persona=0x%lx", (unsigned long)a[0]);
        break;
    case __NR_process_vm_readv:
    case __NR_process_vm_writev:
        APPEND("pid=%d,lvec=%p,liovcnt=%lu,rvec=%p,riovcnt=%lu,flags=0x%lx",
               (int)a[0], (void*)a[1], (unsigned long)a[2],
               (void*)a[3], (unsigned long)a[4], (unsigned long)a[5]);
        break;
    case __NR_kcmp:
        APPEND("pid1=%d,pid2=%d,type=%d,idx1=%lu,idx2=%lu",
               (int)a[0], (int)a[1], (int)a[2], (unsigned long)a[3], (unsigned long)a[4]);
        break;
    case __NR_pidfd_open:
        APPEND("pid=%d,flags=0x%x", (int)a[0], (unsigned int)a[1]);
        break;
    case __NR_pidfd_getfd:
        APPEND("pidfd=%d,targetfd=%d,flags=0x%x", (int)a[0], (int)a[1], (unsigned int)a[2]);
        break;
    case __NR_pidfd_send_signal:
        APPEND("pidfd=%d,sig=%d,info=%p,flags=0x%x",
               (int)a[0], (int)a[1], (void*)a[2], (unsigned int)a[3]);
        break;

    /* === Memory operations === */
    case __NR_mmap:
        APPEND("addr=%p,length=0x%lx,prot=0x%x,flags=0x%x,fd=%d,offset=0x%lx",
               (void*)a[0], (unsigned long)a[1], (unsigned int)a[2],
               (unsigned int)a[3], (int)a[4], (unsigned long)a[5]);
        break;
    case __NR_munmap:
        APPEND("addr=%p,length=0x%lx", (void*)a[0], (unsigned long)a[1]);
        break;
    case __NR_mprotect:
    case __NR_pkey_mprotect:
        APPEND("addr=%p,len=0x%lx,prot=0x%x",
               (void*)a[0], (unsigned long)a[1], (unsigned int)a[2]);
        break;
    case __NR_mremap:
        APPEND("old_addr=%p,old_size=0x%lx,new_size=0x%lx,flags=0x%x,new_addr=%p",
               (void*)a[0], (unsigned long)a[1], (unsigned long)a[2],
               (unsigned int)a[3], (void*)a[4]);
        break;
    case __NR_brk:
        APPEND("brk=%p", (void*)a[0]);
        break;
    case __NR_madvise:
        APPEND("addr=%p,length=0x%lx,advice=%d",
               (void*)a[0], (unsigned long)a[1], (int)a[2]);
        break;
    case __NR_mlock:
    case __NR_mlock2:
        APPEND("addr=%p,len=0x%lx", (void*)a[0], (unsigned long)a[1]);
        break;
    case __NR_munlock:
        APPEND("addr=%p,len=0x%lx", (void*)a[0], (unsigned long)a[1]);
        break;
    case __NR_msync:
        APPEND("addr=%p,length=0x%lx,flags=0x%x",
               (void*)a[0], (unsigned long)a[1], (unsigned int)a[2]);
        break;
    case __NR_memfd_create:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("name=\"%s\",flags=0x%x", tmp2, (unsigned int)a[1]);
        break;
    case __NR_getrandom:
        APPEND("buf=%p,count=%lu,flags=0x%x",
               (void*)a[0], (unsigned long)a[1], (unsigned int)a[2]);
        break;

    /* === Signal operations === */
    case __NR_kill:
        APPEND("pid=%d,sig=%d", (int)a[0], (int)a[1]);
        break;
    case __NR_tkill:
        APPEND("tid=%d,sig=%d", (int)a[0], (int)a[1]);
        break;
    case __NR_tgkill:
        APPEND("tgid=%d,tid=%d,sig=%d", (int)a[0], (int)a[1], (int)a[2]);
        break;
    case __NR_rt_sigaction:
        APPEND("signum=%d,act=%p,oldact=%p,sigsetsize=%lu",
               (int)a[0], (void*)a[1], (void*)a[2], (unsigned long)a[3]);
        break;
    case __NR_rt_sigprocmask:
        APPEND("how=%d,set=%p,oldset=%p,sigsetsize=%lu",
               (int)a[0], (void*)a[1], (void*)a[2], (unsigned long)a[3]);
        break;
    case __NR_sigaltstack:
        APPEND("ss=%p,old_ss=%p", (void*)a[0], (void*)a[1]);
        break;
    case __NR_rt_tgsigqueueinfo:
        APPEND("tgid=%d,tid=%d,sig=%d,info=%p",
               (int)a[0], (int)a[1], (int)a[2], (void*)a[3]);
        break;

    /* === Network operations === */
    case __NR_socket:
        APPEND("domain=%d,type=%d,protocol=%d", (int)a[0], (int)a[1], (int)a[2]);
        break;
    case __NR_socketpair:
        APPEND("domain=%d,type=%d,protocol=%d,sv=%p",
               (int)a[0], (int)a[1], (int)a[2], (void*)a[3]);
        break;
    case __NR_bind:
        APPEND("sockfd=%d,addr=%p,addrlen=%u",
               (int)a[0], (void*)a[1], (unsigned int)a[2]);
        break;
    case __NR_listen:
        APPEND("sockfd=%d,backlog=%d", (int)a[0], (int)a[1]);
        break;
    case __NR_accept:
    case __NR_accept4:
        APPEND("sockfd=%d,addr=%p,addrlen=%p,flags=0x%x",
               (int)a[0], (void*)a[1], (void*)a[2], (unsigned int)a[3]);
        break;
    case __NR_connect:
        APPEND("sockfd=%d,addr=%p,addrlen=%u",
               (int)a[0], (void*)a[1], (unsigned int)a[2]);
        break;
    case __NR_getsockname:
    case __NR_getpeername:
        APPEND("sockfd=%d,addr=%p,addrlen=%p",
               (int)a[0], (void*)a[1], (void*)a[2]);
        break;
    case __NR_sendto:
        APPEND("sockfd=%d,buf=%p,len=%lu,flags=0x%x,dest_addr=%p,addrlen=%u",
               (int)a[0], (void*)a[1], (unsigned long)a[2],
               (unsigned int)a[3], (void*)a[4], (unsigned int)a[5]);
        break;
    case __NR_recvfrom:
        APPEND("sockfd=%d,buf=%p,len=%lu,flags=0x%x,src_addr=%p,addrlen=%p",
               (int)a[0], (void*)a[1], (unsigned long)a[2],
               (unsigned int)a[3], (void*)a[4], (void*)a[5]);
        break;
    case __NR_sendmsg:
    case __NR_recvmsg:
        APPEND("sockfd=%d,msg=%p,flags=0x%x",
               (int)a[0], (void*)a[1], (unsigned int)a[2]);
        break;
    case __NR_setsockopt:
        APPEND("sockfd=%d,level=%d,optname=%d,optval=%p,optlen=%u",
               (int)a[0], (int)a[1], (int)a[2], (void*)a[3], (unsigned int)a[4]);
        break;
    case __NR_getsockopt:
        APPEND("sockfd=%d,level=%d,optname=%d,optval=%p,optlen=%p",
               (int)a[0], (int)a[1], (int)a[2], (void*)a[3], (void*)a[4]);
        break;
    case __NR_shutdown:
        APPEND("sockfd=%d,how=%d", (int)a[0], (int)a[1]);
        break;
    case __NR_sendmmsg:
        APPEND("sockfd=%d,msgvec=%p,vlen=%u,flags=0x%x",
               (int)a[0], (void*)a[1], (unsigned int)a[2], (unsigned int)a[3]);
        break;
    case __NR_recvmmsg:
        APPEND("sockfd=%d,msgvec=%p,vlen=%u,flags=0x%x,timeout=%p",
               (int)a[0], (void*)a[1], (unsigned int)a[2],
               (unsigned int)a[3], (void*)a[4]);
        break;

    /* === Mount / FS === */
    case __NR_mount:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        {
            char src_esc[MAX_ARG_STR];
            kp_memcpy(src_esc, tmp2, sizeof(src_esc));
            READ_STR(tmp, a[1]);
            json_escape(tmp, tmp2, sizeof(tmp2));
            APPEND("source=\"%s\",target=\"%s\",fstype=%p,flags=0x%lx,data=%p",
                   src_esc, tmp2, (void*)a[2], (unsigned long)a[3], (void*)a[4]);
        }
        break;
    case __NR_umount2:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("target=\"%s\",flags=0x%x", tmp2, (unsigned int)a[1]);
        break;
    case __NR_pivot_root:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        {
            char new_esc[MAX_ARG_STR];
            kp_memcpy(new_esc, tmp2, sizeof(new_esc));
            READ_STR(tmp, a[1]);
            json_escape(tmp, tmp2, sizeof(tmp2));
            APPEND("new_root=\"%s\",put_old=\"%s\"", new_esc, tmp2);
        }
        break;
    case __NR_setns:
        APPEND("fd=%d,nstype=0x%x", (int)a[0], (unsigned int)a[1]);
        break;
    case __NR_syncfs:
        APPEND("fd=%d", (int)a[0]);
        break;
    case __NR_fsync:
    case __NR_fdatasync:
        APPEND("fd=%d", (int)a[0]);
        break;

    /* === Module / Security === */
    case __NR_init_module:
        APPEND("module_image=%p,len=%lu,params=%p",
               (void*)a[0], (unsigned long)a[1], (void*)a[2]);
        break;
    case __NR_finit_module:
        APPEND("fd=%d,params=%p,flags=0x%x", (int)a[0], (void*)a[1], (unsigned int)a[2]);
        break;
    case __NR_delete_module:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("name=\"%s\",flags=0x%x", tmp2, (unsigned int)a[1]);
        break;
    case __NR_seccomp:
        APPEND("op=%u,flags=0x%x,args=%p", (unsigned int)a[0], (unsigned int)a[1], (void*)a[2]);
        break;
    case __NR_bpf:
        APPEND("cmd=%d,attr=%p,size=%u", (int)a[0], (void*)a[1], (unsigned int)a[2]);
        break;
    case __NR_perf_event_open:
        APPEND("attr=%p,pid=%d,cpu=%d,group_fd=%d,flags=0x%lx",
               (void*)a[0], (int)a[1], (int)a[2], (int)a[3], (unsigned long)a[4]);
        break;
    case __NR_capget:
        APPEND("hdrp=%p,datap=%p", (void*)a[0], (void*)a[1]);
        break;
    case __NR_capset:
        APPEND("hdrp=%p,datap=%p", (void*)a[0], (void*)a[1]);
        break;
    case __NR_setpriority:
        APPEND("which=%d,who=%d,prio=%d", (int)a[0], (int)a[1], (int)a[2]);
        break;
    case __NR_getpriority:
        APPEND("which=%d,who=%d", (int)a[0], (int)a[1]);
        break;

    /* === IPC === */
    case __NR_futex:
        APPEND("uaddr=%p,op=%d,val=%d,timeout=%p,uaddr2=%p,val3=%d",
               (void*)a[0], (int)a[1], (int)a[2], (void*)a[3], (void*)a[4], (int)a[5]);
        break;
    case __NR_pipe2:
        APPEND("pipefd=%p,flags=0x%x", (void*)a[0], (unsigned int)a[1]);
        break;
    case __NR_epoll_create1:
        APPEND("flags=0x%x", (unsigned int)a[0]);
        break;
    case __NR_epoll_ctl:
        APPEND("epfd=%d,op=%d,fd=%d,event=%p",
               (int)a[0], (int)a[1], (int)a[2], (void*)a[3]);
        break;
    case __NR_epoll_pwait:
        APPEND("epfd=%d,events=%p,maxevents=%d,timeout=%d,sigmask=%p",
               (int)a[0], (void*)a[1], (int)a[2], (int)a[3], (void*)a[4]);
        break;
    case __NR_eventfd2:
        APPEND("initval=%u,flags=0x%x", (unsigned int)a[0], (unsigned int)a[1]);
        break;
    case __NR_inotify_init1:
        APPEND("flags=0x%x", (unsigned int)a[0]);
        break;
    case __NR_inotify_add_watch:
        READ_STR(tmp, a[1]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("fd=%d,pathname=\"%s\",mask=0x%x",
               (int)a[0], tmp2, (unsigned int)a[2]);
        break;
    case __NR_inotify_rm_watch:
        APPEND("fd=%d,wd=%d", (int)a[0], (int)a[1]);
        break;
    case __NR_shmget:
        APPEND("key=%d,size=%lu,shmflg=0x%x",
               (int)a[0], (unsigned long)a[1], (unsigned int)a[2]);
        break;
    case __NR_shmat:
        APPEND("shmid=%d,shmaddr=%p,shmflg=0x%x",
               (int)a[0], (void*)a[1], (unsigned int)a[2]);
        break;
    case __NR_shmdt:
        APPEND("shmaddr=%p", (void*)a[0]);
        break;
    case __NR_shmctl:
        APPEND("shmid=%d,cmd=%d,buf=%p", (int)a[0], (int)a[1], (void*)a[2]);
        break;
    case __NR_semget:
        APPEND("key=%d,nsems=%d,semflg=0x%x", (int)a[0], (int)a[1], (unsigned int)a[2]);
        break;
    case __NR_msgget:
        APPEND("key=%d,msgflg=0x%x", (int)a[0], (unsigned int)a[1]);
        break;
    case __NR_msgsnd:
        APPEND("msqid=%d,msgp=%p,msgsz=%lu,msgflg=0x%x",
               (int)a[0], (void*)a[1], (unsigned long)a[2], (unsigned int)a[3]);
        break;
    case __NR_msgrcv:
        APPEND("msqid=%d,msgp=%p,msgsz=%lu,msgtyp=%ld,msgflg=0x%x",
               (int)a[0], (void*)a[1], (unsigned long)a[2],
               (long)a[3], (unsigned int)a[4]);
        break;

    /* === Timer / Clock === */
    case __NR_nanosleep:
    case __NR_clock_nanosleep:
        APPEND("req=%p,rem=%p", (void*)a[0], (void*)a[1]);
        break;
    case __NR_clock_gettime:
        APPEND("clk_id=%d,tp=%p", (int)a[0], (void*)a[1]);
        break;
    case __NR_gettimeofday:
        APPEND("tv=%p,tz=%p", (void*)a[0], (void*)a[1]);
        break;
    case __NR_timerfd_create:
        APPEND("clockid=%d,flags=0x%x", (int)a[0], (unsigned int)a[1]);
        break;
    case __NR_setitimer:
        APPEND("which=%d,new_value=%p,old_value=%p",
               (int)a[0], (void*)a[1], (void*)a[2]);
        break;

    /* === Extended attributes === */
    case __NR_setxattr:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        {
            char path_esc[MAX_ARG_STR];
            kp_memcpy(path_esc, tmp2, sizeof(path_esc));
            READ_STR(tmp, a[1]);
            json_escape(tmp, tmp2, sizeof(tmp2));
            APPEND("path=\"%s\",name=\"%s\",value=%p,size=%lu,flags=0x%x",
                   path_esc, tmp2, (void*)a[2], (unsigned long)a[3], (unsigned int)a[4]);
        }
        break;
    case __NR_getxattr:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        {
            char path_esc[MAX_ARG_STR];
            kp_memcpy(path_esc, tmp2, sizeof(path_esc));
            READ_STR(tmp, a[1]);
            json_escape(tmp, tmp2, sizeof(tmp2));
            APPEND("path=\"%s\",name=\"%s\",value=%p,size=%lu",
                   path_esc, tmp2, (void*)a[2], (unsigned long)a[3]);
        }
        break;

    /* === io_uring === */
    case __NR_io_uring_setup:
        APPEND("entries=%u,params=%p", (unsigned int)a[0], (void*)a[1]);
        break;
    case __NR_io_uring_enter:
        APPEND("fd=%d,to_submit=%u,min_complete=%u,flags=0x%x,sig=%p,sigsz=%lu",
               (int)a[0], (unsigned int)a[1], (unsigned int)a[2],
               (unsigned int)a[3], (void*)a[4], (unsigned long)a[5]);
        break;
    case __NR_io_uring_register:
        APPEND("fd=%d,opcode=%u,arg=%p,nr_args=%u",
               (int)a[0], (unsigned int)a[1], (void*)a[2], (unsigned int)a[3]);
        break;

    /* === Misc === */
    case __NR_uname:
        APPEND("buf=%p", (void*)a[0]);
        break;
    case __NR_sysinfo:
        APPEND("info=%p", (void*)a[0]);
        break;
    case __NR_umask:
        APPEND("mask=0%o", (unsigned int)a[0]);
        break;
    case __NR_getcpu:
        APPEND("cpu=%p,node=%p", (void*)a[0], (void*)a[1]);
        break;
    case __NR_syslog:
        APPEND("type=%d,buf=%p,len=%d", (int)a[0], (void*)a[1], (int)a[2]);
        break;
    case __NR_reboot:
        APPEND("magic1=0x%x,magic2=0x%x,cmd=0x%x,arg=%p",
               (unsigned int)a[0], (unsigned int)a[1], (unsigned int)a[2], (void*)a[3]);
        break;
    case __NR_acct:
        READ_STR(tmp, a[0]);
        json_escape(tmp, tmp2, sizeof(tmp2));
        APPEND("name=\"%s\"", tmp2);
        break;

    default:
        APPEND("a0=0x%llx,a1=0x%llx,a2=0x%llx,a3=0x%llx,a4=0x%llx,a5=0x%llx",
               a[0], a[1], a[2], a[3], a[4], a[5]);
        break;
    }

#undef APPEND
#undef READ_STR
}

/* ================================================================
 * Syscall hook callback - v9 fix: use syscall_args() for correct arg extraction
 * ================================================================ */

static void before_syscall_from_hook(void *fargs_raw, int nr)
{
    struct svc_event ev;
    uint64_t *real_args;
    int pid, tid;
    unsigned int uid;

    if (!g_running) return;

    /* Re-entrancy guard */
    if (g_in_hook) return;
    g_in_hook = 1;

    /* Get process info */
    pid = get_current_pid();
    tid = get_current_tid();
    uid = get_current_uid();

    /* Filter check */
    if (g_target_pid && pid != g_target_pid) { g_in_hook = 0; return; }
    if (g_target_uid && uid != g_target_uid) { g_in_hook = 0; return; }

    if (g_target_comm[0]) {
        char comm[MAX_COMM_LEN];
        get_current_comm(comm, sizeof(comm));
        {
            int ci;
            for (ci = 0; ci < MAX_COMM_LEN; ci++) {
                if (g_target_comm[ci] != comm[ci]) { g_in_hook = 0; return; }
                if (!g_target_comm[ci]) break;
            }
        }
    }

    /* Initialize event */
    kp_memset(&ev, 0, sizeof(ev));
    ev.timestamp = get_timestamp_ns();
    ev.seq = __sync_fetch_and_add(&g_seq, 1);
    ev.nr = nr;
    ev.pid = pid;
    ev.tid = tid;
    ev.uid = uid;
    get_current_comm(ev.comm, sizeof(ev.comm));

    /* v9 FIX: use syscall_args() to get real arguments */
    real_args = syscall_args(fargs_raw);
    if (real_args) {
        ev.args[0] = real_args[0];
        ev.args[1] = real_args[1];
        ev.args[2] = real_args[2];
        ev.args[3] = real_args[3];
        ev.args[4] = real_args[4];
        ev.args[5] = real_args[5];
    }

    /* Deep parse arguments */
    deep_parse_args(nr, ev.args, ev.arg_detail, sizeof(ev.arg_detail));

    /* Capture caller PC/LR */
    capture_caller(&ev, fargs_raw);

    /* Resolve SO + offset */
    resolve_caller(&ev);

    /* Push to ring buffer */
    push_event(&ev);

    g_in_hook = 0;
}

static void before_any(hook_fargs6_t *args, void *udata)
{
    before_syscall_from_hook((void *)args, (int)(unsigned long)udata);
}

/* ================================================================
 * Hook entry macros - one before_NR function per syscall number
 * ================================================================ */

#define HOOK_ENTRY(NR) \
    static void before_##NR(hook_fargs6_t *args, void *udata) { \
        before_syscall_from_hook((void *)args, NR); \
    }

HOOK_ENTRY(0)
HOOK_ENTRY(1)
HOOK_ENTRY(2)
HOOK_ENTRY(3)
HOOK_ENTRY(4)

HOOK_ENTRY(5)
HOOK_ENTRY(8)
HOOK_ENTRY(11)
HOOK_ENTRY(14)
HOOK_ENTRY(17)

HOOK_ENTRY(19)
HOOK_ENTRY(20)
HOOK_ENTRY(21)
HOOK_ENTRY(22)
HOOK_ENTRY(23)

HOOK_ENTRY(24)
HOOK_ENTRY(25)
HOOK_ENTRY(26)
HOOK_ENTRY(27)
HOOK_ENTRY(28)

HOOK_ENTRY(29)
HOOK_ENTRY(30)
HOOK_ENTRY(31)
HOOK_ENTRY(32)
HOOK_ENTRY(33)

HOOK_ENTRY(34)
HOOK_ENTRY(35)
HOOK_ENTRY(36)
HOOK_ENTRY(37)
HOOK_ENTRY(38)

HOOK_ENTRY(39)
HOOK_ENTRY(40)
HOOK_ENTRY(43)
HOOK_ENTRY(44)
HOOK_ENTRY(45)

HOOK_ENTRY(46)
HOOK_ENTRY(47)
HOOK_ENTRY(48)
HOOK_ENTRY(49)
HOOK_ENTRY(50)

HOOK_ENTRY(51)
HOOK_ENTRY(52)
HOOK_ENTRY(53)
HOOK_ENTRY(54)
HOOK_ENTRY(55)

HOOK_ENTRY(56)
HOOK_ENTRY(57)
HOOK_ENTRY(59)
HOOK_ENTRY(61)
HOOK_ENTRY(62)

HOOK_ENTRY(63)
HOOK_ENTRY(64)
HOOK_ENTRY(65)
HOOK_ENTRY(66)
HOOK_ENTRY(67)

HOOK_ENTRY(68)
HOOK_ENTRY(71)
HOOK_ENTRY(72)
HOOK_ENTRY(73)
HOOK_ENTRY(76)

HOOK_ENTRY(78)
HOOK_ENTRY(79)
HOOK_ENTRY(80)
HOOK_ENTRY(81)
HOOK_ENTRY(82)

HOOK_ENTRY(83)
HOOK_ENTRY(85)
HOOK_ENTRY(88)
HOOK_ENTRY(89)
HOOK_ENTRY(90)

HOOK_ENTRY(91)
HOOK_ENTRY(93)
HOOK_ENTRY(94)
HOOK_ENTRY(95)
HOOK_ENTRY(96)

HOOK_ENTRY(97)
HOOK_ENTRY(98)
HOOK_ENTRY(99)
HOOK_ENTRY(100)
HOOK_ENTRY(101)

HOOK_ENTRY(103)
HOOK_ENTRY(105)
HOOK_ENTRY(106)
HOOK_ENTRY(113)
HOOK_ENTRY(114)

HOOK_ENTRY(115)
HOOK_ENTRY(116)
HOOK_ENTRY(117)
HOOK_ENTRY(124)
HOOK_ENTRY(129)

HOOK_ENTRY(130)
HOOK_ENTRY(131)
HOOK_ENTRY(132)
HOOK_ENTRY(134)
HOOK_ENTRY(135)

HOOK_ENTRY(140)
HOOK_ENTRY(141)
HOOK_ENTRY(142)
HOOK_ENTRY(146)
HOOK_ENTRY(147)

HOOK_ENTRY(153)
HOOK_ENTRY(154)
HOOK_ENTRY(157)
HOOK_ENTRY(160)
HOOK_ENTRY(163)

HOOK_ENTRY(164)
HOOK_ENTRY(166)
HOOK_ENTRY(167)
HOOK_ENTRY(168)
HOOK_ENTRY(169)

HOOK_ENTRY(172)
HOOK_ENTRY(173)
HOOK_ENTRY(174)
HOOK_ENTRY(175)
HOOK_ENTRY(176)

HOOK_ENTRY(177)
HOOK_ENTRY(178)
HOOK_ENTRY(179)
HOOK_ENTRY(186)
HOOK_ENTRY(187)

HOOK_ENTRY(188)
HOOK_ENTRY(189)
HOOK_ENTRY(190)
HOOK_ENTRY(191)
HOOK_ENTRY(194)

HOOK_ENTRY(195)
HOOK_ENTRY(196)
HOOK_ENTRY(197)
HOOK_ENTRY(198)
HOOK_ENTRY(199)

HOOK_ENTRY(200)
HOOK_ENTRY(201)
HOOK_ENTRY(202)
HOOK_ENTRY(203)
HOOK_ENTRY(204)

HOOK_ENTRY(205)
HOOK_ENTRY(206)
HOOK_ENTRY(207)
HOOK_ENTRY(208)
HOOK_ENTRY(209)

HOOK_ENTRY(210)
HOOK_ENTRY(211)
HOOK_ENTRY(212)
HOOK_ENTRY(214)
HOOK_ENTRY(215)

HOOK_ENTRY(216)
HOOK_ENTRY(220)
HOOK_ENTRY(221)
HOOK_ENTRY(222)
HOOK_ENTRY(226)

HOOK_ENTRY(227)
HOOK_ENTRY(228)
HOOK_ENTRY(229)
HOOK_ENTRY(233)
HOOK_ENTRY(240)

HOOK_ENTRY(241)
HOOK_ENTRY(242)
HOOK_ENTRY(260)
HOOK_ENTRY(261)
HOOK_ENTRY(268)

HOOK_ENTRY(269)
HOOK_ENTRY(270)
HOOK_ENTRY(271)
HOOK_ENTRY(272)
HOOK_ENTRY(273)

HOOK_ENTRY(276)
HOOK_ENTRY(277)
HOOK_ENTRY(278)
HOOK_ENTRY(279)
HOOK_ENTRY(280)

HOOK_ENTRY(281)
HOOK_ENTRY(284)
HOOK_ENTRY(285)
HOOK_ENTRY(291)
HOOK_ENTRY(424)

HOOK_ENTRY(425)
HOOK_ENTRY(426)
HOOK_ENTRY(427)
HOOK_ENTRY(434)
HOOK_ENTRY(435)

HOOK_ENTRY(436)
HOOK_ENTRY(437)
HOOK_ENTRY(438)
HOOK_ENTRY(439)


/* ================================================================
 * Hook install / remove - v9 fix: correct API signatures
 *   hook_syscalln(nr, narg, before, after, udata)  -> 5 params
 *   unhook_syscalln(nr, before, after)             -> 3 params
 * ================================================================ */

static int install_hook(int nr)
{
    int ret;
    ret = hook_syscalln(nr, 6, (void *)before_any, NULL, (void *)(unsigned long)nr);
    if (ret == 0) {
        if (g_hook_count < MAX_HOOKS) {
            g_hooked_nrs[g_hook_count++] = nr;
        }
        bitmap_set(nr);
    }
    return ret;
}

static void remove_hook(int nr)
{
    unhook_syscalln(nr, (void *)before_any, NULL);
    bitmap_clear(nr);
}

static void remove_all_hooks(void)
{
    int i;
    for (i = 0; i < g_hook_count; i++) {
        remove_hook(g_hooked_nrs[i]);
    }
    g_hook_count = 0;
}

/* ================================================================
 * Tier / Preset definitions
 * ================================================================ */

static const int g_tier1_nrs[] = {
    56, 57, 63, 64, 221, 281, 220, 435, 129, 131, 117, 198, 203, 200, 201, 
    206, 207, 211, 212, 222, 226, 215, 40, 39, 167, 277, 280, 105, 106, 273, 
    48, 439, 35, 34, 53, 54, 78, 36, 37, 38, 276, 61, 93, 94, 260, 
    95, 270, 271
};
static const int g_tier1_count = 48;

static const int g_tier2_nrs[] = {
    29, 25, 79, 80, 291, 43, 44, 62, 65, 66, 67, 68, 71, 85, 88, 
    214, 216, 233, 228, 229, 98, 20, 21, 22, 23, 24, 59, 19, 26, 27, 
    28, 134, 135, 130, 132, 240, 261, 163, 164, 146, 147, 140, 141, 160, 167, 
    179, 113, 114, 115, 169, 101, 103, 116, 208, 209, 210, 242, 269, 243, 268, 
    97, 51, 49, 50, 166, 82, 83, 81, 278, 279, 241, 425, 426, 427, 424, 
    434, 436, 437, 438, 194, 195, 196, 197, 186, 187, 188, 189, 190, 191
};
static const int g_tier2_count = 89;

static int install_tier1(void)
{
    int i, ok = 0;
    for (i = 0; i < g_tier1_count; i++) {
        if (install_hook(g_tier1_nrs[i]) == 0) ok++;
    }
    return ok;
}

static int install_tier2(void)
{
    int i, ok = 0;
    for (i = 0; i < g_tier2_count; i++) {
        if (install_hook(g_tier2_nrs[i]) == 0) ok++;
    }
    return ok;
}

static int install_all(void)
{
    return install_tier1() + install_tier2();
}

/* ================================================================
 * Drain events to output buffer as JSON lines
 * ================================================================ */

static void drain_events(void)
{
    struct svc_event ev;
    char detail_esc[1024];
    char so_esc[512];
    char comm_esc[64];
    int count = 0;

    g_outpos = 0;
    g_outbuf[0] = '\0';

    while (pop_event(&ev) && g_outpos < OUTPUT_BUF_SIZE - 2048) {
        json_escape(ev.arg_detail, detail_esc, sizeof(detail_esc));
        json_escape(ev.caller_so, so_esc, sizeof(so_esc));
        json_escape(ev.comm, comm_esc, sizeof(comm_esc));

        g_outpos += __builtin_snprintf(g_outbuf + g_outpos, OUTPUT_BUF_SIZE - g_outpos,
            "{\"seq\":%u,\"ts\":%llu,\"nr\":%d,\"name\":\"%s\","
            "\"pid\":%d,\"tid\":%d,\"uid\":%u,\"comm\":\"%s\","
            "\"args\":\"%s\","
            "\"callerPC\":\"0x%llx\",\"callerLR\":\"0x%llx\","
            "\"callerSo\":\"%s\",\"callerOffset\":\"0x%llx\"}\n",
            ev.seq, ev.timestamp, ev.nr, get_syscall_name(ev.nr),
            ev.pid, ev.tid, ev.uid, comm_esc,
            detail_esc,
            ev.caller_pc, ev.caller_lr,
            so_esc, ev.caller_offset);
        count++;
    }

    if (count == 0) {
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"status\":\"no_events\",\"dropped\":%d}\n", g_ev_dropped);
    }
}

static void output_status(void)
{
    g_outpos = 0;
    g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
        "{\"version\":\"9.0.0\",\"running\":%d,\"hooks\":%d,"
        "\"events\":%d,\"dropped\":%d,\"seq\":%u,"
        "\"target_pid\":%d,\"target_uid\":%u,"
        "\"target_comm\":\"%s\","
        "\"maps_cache_pid\":%d,\"maps_cache_entries\":%d}\n",
        g_running, g_hook_count, g_ev_count, g_ev_dropped, g_seq,
        g_target_pid, g_target_uid, g_target_comm,
        g_maps_cache.pid, g_maps_cache.count);
}

static void apply_preset(const char *name)
{
    int ok;
    g_outpos = 0;

    if (!name) {
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"error\":\"no preset name\"}\n");
        return;
    }

    /* Compare preset names manually */
    {
        int match_tier1 = (name[0]=='t' && name[1]=='i' && name[2]=='e' && name[3]=='r' && name[4]=='1' && name[5]=='\0');
        int match_tier2 = (name[0]=='t' && name[1]=='i' && name[2]=='e' && name[3]=='r' && name[4]=='2' && name[5]=='\0');
        int match_all = (name[0]=='a' && name[1]=='l' && name[2]=='l' && name[3]=='\0');

        if (match_tier1) ok = install_tier1();
        else if (match_tier2) ok = install_all();
        else if (match_all) ok = install_all();
        else {
            g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
                "{\"error\":\"unknown preset: %s\"}\n", name);
            return;
        }
    }

    g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
        "{\"preset\":\"%s\",\"hooks_installed\":%d}\n", name, ok);
}

static int str_eq(const char *a, const char *b)
{
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return (*a == *b);
}

static int simple_atoi(const char *s)
{
    int val = 0, neg = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') { val = val * 10 + (*s - '0'); s++; }
    return neg ? -val : val;
}

static const char *next_token(const char *s)
{
    while (*s && *s != ' ' && *s != '\t') s++;
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* ================================================================
 * CTL0 command dispatcher
 * ================================================================ */

static void ctl0_dispatch(const char *cmd, char *outbuf, int outlen)
{
    g_outbuf[0] = '\0';
    g_outpos = 0;

    if (!cmd || !cmd[0]) {
        output_status();
        return;
    }

    if (str_eq(cmd, "status")) {
        output_status();
    }
    else if (str_eq(cmd, "start")) {
        g_running = 1;
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"action\":\"start\",\"running\":1,\"hooks\":%d}\n", g_hook_count);
    }
    else if (str_eq(cmd, "stop")) {
        g_running = 0;
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"action\":\"stop\",\"running\":0}\n");
    }
    else if (str_eq(cmd, "read")) {
        drain_events();
    }
    else if (str_eq(cmd, "clear")) {
        g_ev_head = 0;
        g_ev_tail = 0;
        g_ev_count = 0;
        g_ev_dropped = 0;
        g_seq = 0;
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"action\":\"clear\",\"events\":0}\n");
    }
    else if (cmd[0]=='p' && cmd[1]=='i' && cmd[2]=='d' && (cmd[3]==' ' || cmd[3]=='\0')) {
        if (cmd[3] == ' ') {
            g_target_pid = simple_atoi(cmd + 4);
            /* Invalidate maps cache for new target */
            g_maps_cache.pid = 0;
            g_maps_cache.count = 0;
        }
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"target_pid\":%d}\n", g_target_pid);
    }
    else if (cmd[0]=='u' && cmd[1]=='i' && cmd[2]=='d' && (cmd[3]==' ' || cmd[3]=='\0')) {
        if (cmd[3] == ' ') g_target_uid = (unsigned int)simple_atoi(cmd + 4);
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"target_uid\":%u}\n", g_target_uid);
    }
    else if (cmd[0]=='c' && cmd[1]=='o' && cmd[2]=='m' && cmd[3]=='m' && (cmd[4]==' ' || cmd[4]=='\0')) {
        if (cmd[4] == ' ') {
            int ci;
            const char *src = cmd + 5;
            for (ci = 0; ci < MAX_COMM_LEN - 1 && src[ci]; ci++)
                g_target_comm[ci] = src[ci];
            g_target_comm[ci] = '\0';
        }
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"target_comm\":\"%s\"}\n", g_target_comm);
    }
    else if (cmd[0]=='p' && cmd[1]=='r' && cmd[2]=='e' && cmd[3]=='s' && cmd[4]=='e' && cmd[5]=='t' && cmd[6]==' ') {
        apply_preset(cmd + 7);
    }
    else if (cmd[0]=='h' && cmd[1]=='o' && cmd[2]=='o' && cmd[3]=='k' && cmd[4]==' ') {
        int nr = simple_atoi(cmd + 5);
        int ret = install_hook(nr);
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"action\":\"hook\",\"nr\":%d,\"result\":%d}\n", nr, ret);
    }
    else if (cmd[0]=='u' && cmd[1]=='n' && cmd[2]=='h' && cmd[3]=='o' && cmd[4]=='o' && cmd[5]=='k' && cmd[6]==' ') {
        int nr = simple_atoi(cmd + 7);
        remove_hook(nr);
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"action\":\"unhook\",\"nr\":%d}\n", nr);
    }
    else if (str_eq(cmd, "hooks")) {
        int i;
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE, "{\"hooks\":[");
        for (i = 0; i < g_hook_count && g_outpos < OUTPUT_BUF_SIZE - 64; i++) {
            if (i > 0) g_outpos += __builtin_snprintf(g_outbuf + g_outpos, OUTPUT_BUF_SIZE - g_outpos, ",");
            g_outpos += __builtin_snprintf(g_outbuf + g_outpos, OUTPUT_BUF_SIZE - g_outpos,
                "{\"nr\":%d,\"name\":\"%s\"}", g_hooked_nrs[i], get_syscall_name(g_hooked_nrs[i]));
        }
        g_outpos += __builtin_snprintf(g_outbuf + g_outpos, OUTPUT_BUF_SIZE - g_outpos, "]}\n");
    }
    else if (str_eq(cmd, "maps_flush")) {
        g_maps_cache.pid = 0;
        g_maps_cache.count = 0;
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"action\":\"maps_flush\",\"ok\":1}\n");
    }
    else if (str_eq(cmd, "help")) {
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"commands\":["
            "\"status\",\"start\",\"stop\",\"read\",\"clear\","
            "\"pid <N>\",\"uid <N>\",\"comm <str>\","
            "\"preset tier1|tier2|all\","
            "\"hook <nr>\",\"unhook <nr>\",\"hooks\","
            "\"maps_flush\",\"help\""
            "]}\n");
    }
    else {
        g_outpos = __builtin_snprintf(g_outbuf, OUTPUT_BUF_SIZE,
            "{\"error\":\"unknown command\",\"cmd\":\"%s\"}\n", cmd);
    }
}

/* ================================================================
 * KPM Entry Points
 * ================================================================ */

static long __attribute__((used)) svc_init(const char *args, const char *event, void *reserved)
{
    g_running = 0;
    g_hook_count = 0;
    g_ev_head = 0;
    g_ev_tail = 0;
    g_ev_count = 0;
    g_ev_dropped = 0;
    g_seq = 0;
    g_in_hook = 0;
    kp_memset(g_bitmap, 0, sizeof(g_bitmap));
    kp_memset(g_target_comm, 0, sizeof(g_target_comm));
    kp_memset(&g_maps_cache, 0, sizeof(g_maps_cache));
    g_target_pid = 0;
    g_target_uid = 0;
    g_initialized = 1;
    pr_info("svc_monitor v9.0.0 loaded\n");
    return 0;
}

static long __attribute__((used)) svc_ctl0(const char *args, char *outbuf, int outlen)
{
    if (!g_initialized) return -1;

    ctl0_dispatch(args, outbuf, outlen);

    /* Copy output */
    if (outbuf && outlen > 0 && g_outpos > 0) {
        int copy_len = g_outpos < outlen - 1 ? g_outpos : outlen - 1;
        kp_memcpy(outbuf, g_outbuf, copy_len);
        outbuf[copy_len] = '\0';
    }
    return 0;
}

static long __attribute__((used)) svc_exit(void *reserved)
{
    g_running = 0;
    remove_all_hooks();
    g_initialized = 0;
    pr_info("svc_monitor v9.0.0 unloaded\n");
    return 0;
}

KPM_INIT(svc_init);
KPM_CTL0(svc_ctl0);
KPM_EXIT(svc_exit);
