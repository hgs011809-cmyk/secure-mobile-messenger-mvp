/* PRIVATE trusted-CI observation only: neither atomic lifecycle proof nor
 * adversarial-host protection. No signals, namespace entry or privileged fallback.
 * Build on Linux with a C11 compiler; no external libraries. Not executed here.
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Local ABI definition avoids a dependency on recent linux/openat2.h. */
struct probe_open_how { uint64_t flags, mode, resolve; };
#define RESOLVE_NO_XDEV_P 0x01U
#define RESOLVE_NO_SYMLINKS_P 0x04U
#define RESOLVE_BENEATH_P 0x08U
#define CGROUP2_MAGIC_P 0x63677270L
#define PROC_MAGIC_P 0x9fa0L
#define MAX_READ 65536U
#define WINDOW_NS INT64_C(30000000000)
struct identity { uint64_t dev, ino; };
struct facts {
    char pid[24], ticks[24], state, membership[128];
    char ns[4][64], mountdev[48];
    struct identity proc, cg;
};
static int procfd = -1, cgfd = -1, rootfd = -1, selffd = -1, pidfd = -1;
static int64_t deadline;
static const char *gate = "KERNEL_PROOF_UNVERIFIED";
static int64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (int64_t)t.tv_sec * INT64_C(1000000000) + t.tv_nsec;
}
static int remaining_ms(void) {
    int64_t n = now_ns();
    if (n < 0 || n >= deadline) return 0;
    return (int)((deadline - n + 999999) / 1000000);
}
static int send_text(const char *s) {
    size_t n = strlen(s), off = 0;
    while (off < n) {
        struct pollfd p = {STDOUT_FILENO, POLLOUT, 0};
        int ms = remaining_ms();
        if (!ms) return 0;
        int r = poll(&p, 1, ms);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0 || !(p.revents & POLLOUT)) return 0;
        ssize_t k = write(STDOUT_FILENO, s + off, n - off);
        if (k < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (k <= 0) return 0;
        off += (size_t)k;
    }
    return 1;
}
static int blocked(void) {
    char b[160];
    (void)snprintf(b, sizeof b, "{\"version\":1,\"op\":\"blocked\",\"gate\":\"%s\"}\n", gate);
    if (remaining_ms()) (void)send_text(b);
    else { /* bounded, nonblocking best effort; remain blocked on error/partial write */
        size_t n = strlen(b);
        ssize_t sent = write(STDOUT_FILENO, b, n);
        if (sent < 0 || (size_t)sent != n) return 1;
    }
    return 1;
}
static int decimal(const char *s, uint64_t *out) {
    uint64_t v = 0;
    if (!s || !*s || (s[0] == '0' && s[1])) return 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9') return 0;
        unsigned d = (unsigned)(*s - '0');
        if (v > (UINT64_MAX - d) / 10) return 0;
        v = v * 10 + d;
    }
    *out = v;
    return 1;
}
static int exact_id(const char *s) {
    if (strlen(s) != 64) return 0;
    for (size_t i = 0; i < 64; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}
static int live(void) {
    struct pollfd p = {pidfd, POLLIN, 0};
    int r;
    do { r = poll(&p, 1, 0); } while (r < 0 && errno == EINTR && remaining_ms());
    return r == 0 && remaining_ms() > 0;
}
static int child_open(int dir, const char *name) {
#ifdef SYS_openat2
    struct probe_open_how h = {O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0,
        RESOLVE_BENEATH_P | RESOLVE_NO_SYMLINKS_P | RESOLVE_NO_XDEV_P};
    return (int)syscall(SYS_openat2, dir, name, &h, sizeof h);
#else
    (void)dir; (void)name; errno = ENOSYS; return -1;
#endif
}
static int read_at(int dir, const char *name, char *b, size_t cap, int cgroup) {
    int fd = cgroup ? child_open(dir, name) : openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return 0;
    struct stat st;
    struct statfs sf;
    int ok = !fstat(fd, &st) && S_ISREG(st.st_mode) && !fstatfs(fd, &sf)
        && sf.f_type == (cgroup ? CGROUP2_MAGIC_P : PROC_MAGIC_P);
    size_t used = 0;
    while (ok) {
        if (!remaining_ms() || used + 1 >= cap) { ok = 0; break; }
        ssize_t n = read(fd, b + used, cap - used - 1);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = 0; break; }
        if (!n) break;
        if (memchr(b + used, '\0', (size_t)n)) { ok = 0; break; }
        used += (size_t)n;
    }
    close(fd);
    if (!ok) return 0;
    b[used] = '\0';
    return used > 0;
}
static int anchor(int fd, long magic, struct identity *a) {
    struct stat st; struct statfs sf;
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) || fstatfs(fd, &sf) || sf.f_type != magic || !st.st_ino
        || (magic == CGROUP2_MAGIC_P && st.st_nlink == 0)) return 0;
    a->dev = (uint64_t)st.st_dev; a->ino = (uint64_t)st.st_ino;
    return 1;
}
static int ns_read(char out[4][64]) {
    const char *names[] = {"pid", "cgroup", "mnt", "time"};
    for (unsigned i = 0; i < 4; ++i) {
        char p[32]; (void)snprintf(p, sizeof p, "ns/%s", names[i]);
        ssize_t n = readlinkat(selffd, p, out[i], 63);
        if (n <= 0 || n >= 63) return 0;
        out[i][n] = '\0';
        size_t len = strlen(names[i]); uint64_t val;
        if (strncmp(out[i], names[i], len) || strncmp(out[i] + len, ":[", 2)
            || out[i][n - 1] != ']') return 0;
        char digits[32]; size_t count = (size_t)n - len - 3;
        if (!count || count >= sizeof digits) return 0;
        memcpy(digits, out[i] + len + 2, count); digits[count] = '\0';
        if (!decimal(digits, &val) || !val) return 0;
    }
    return 1;
}
static int mount_profile(char device[48], char mountid[24]) {
    char b[MAX_READ];
    if (!read_at(selffd, "mountinfo", b, sizeof b, 0)) return 0;
    unsigned matches = 0;
    char *save = NULL;
    for (char *line = strtok_r(b, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *sep = strstr(line, " - ");
        if (!sep) return 0;
        char *tail = sep + 3;
        if (strncmp(tail, "cgroup2 ", 8)) continue;
        if (++matches != 1) return 0;
        *sep = '\0'; char *sv = NULL; char *fields[6];
        for (unsigned i = 0; i < 6; ++i) {
            fields[i] = strtok_r(i ? NULL : line, " ", &sv);
            if (!fields[i]) return 0;
        }
        uint64_t mid, parent;
        if (strlen(fields[0]) >= 24 || !decimal(fields[0], &mid) || !mid || !decimal(fields[1], &parent)
            || strcmp(fields[3], "/") || strcmp(fields[4], "/sys/fs/cgroup")) return 0;
        strcpy(mountid, fields[0]);
        if (strlen(fields[2]) >= 48) return 0;
        char *colon = strchr(fields[2], ':'); uint64_t maj, min;
        if (!colon || strchr(colon + 1, ':')) return 0;
        *colon = '\0';
        if (!decimal(fields[2], &maj) || !decimal(colon + 1, &min) || maj > UINT_MAX || min > UINT_MAX) return 0;
        (void)snprintf(device, 48, "%" PRIu64 ":%" PRIu64, maj, min);
    }
    return matches == 1;
}
/* Correlate the retained mount-root FD with our own verified mountinfo.
 * Only observer-own fdinfo is read, never target protected files. */
static int root_mount(const char *expected) {
    char name[48], b[4096];
    (void)snprintf(name, sizeof name, "fdinfo/%d", rootfd);
    if (!read_at(selffd, name, b, sizeof b, 0)) return 0;
    char *save = NULL; unsigned found = 0;
    for (char *line = strtok_r(b, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (strncmp(line, "mnt_id:", 7)) continue;
        char *n = line + 7;
        while (*n == ' ' || *n == '\t') ++n;
        uint64_t id;
        if (++found != 1 || !decimal(n, &id) || !id || strcmp(n, expected)) return 0;
    }
    return found == 1;
}
static int bounds(void) {
    const char *files[] = {"memory.max", "memory.swap.max", "cpu.max", "cpu.max.burst", "pids.max", "cgroup.type"};
    const char *values[] = {"1073741824\n", "0\n", "100000 100000\n", "0\n", "128\n", "domain\n"};
    char b[128];
    for (unsigned i = 0; i < 6; ++i)
        if (!read_at(cgfd, files[i], b, sizeof b, 1) || strcmp(b, values[i])) return 0;
    return 1;
}
static int observe(struct facts *f, const char *pid, const char *member) {
    char b[8192], mountid[24];
    memset(f, 0, sizeof *f);
    if (!live() || !anchor(procfd, PROC_MAGIC_P, &f->proc) || !anchor(cgfd, CGROUP2_MAGIC_P, &f->cg)
        || !ns_read(f->ns) || !mount_profile(f->mountdev, mountid) || !root_mount(mountid)) return 0;
    struct identity r;
    if (!anchor(rootfd, CGROUP2_MAGIC_P, &r)) return 0;
    char dev[48]; (void)snprintf(dev, sizeof dev, "%u:%u", major((dev_t)r.dev), minor((dev_t)r.dev));
    if (strcmp(dev, f->mountdev) || r.dev != f->cg.dev) return 0;
    if (!read_at(procfd, "stat", b, sizeof b, 0)) return 0;
    char *space = strchr(b, ' '), *end = strrchr(b, ')');
    if (!space || !end || space >= end || space[1] != '(' || end[1] != ' ') return 0;
    *space = '\0'; if (strcmp(b, pid)) return 0;
    char *sv = NULL; char *token = strtok_r(end + 2, " \n", &sv);
    if (!token || strlen(token) != 1 || !strchr("RSDI", token[0])) return 0;
    f->state = token[0];
    for (unsigned field = 4; field <= 22; ++field) {
        token = strtok_r(NULL, " \n", &sv); if (!token) return 0;
    }
    uint64_t ticks;
    if (!decimal(token, &ticks) || !ticks || strlen(token) >= sizeof f->ticks) return 0;
    strcpy(f->ticks, token); strcpy(f->pid, pid);
    if (!read_at(procfd, "cgroup", b, sizeof b, 0)) return 0;
    char expected[160]; (void)snprintf(expected, sizeof expected, "0::%s\n", member);
    if (strcmp(b, expected)) return 0;
    strcpy(f->membership, member);
    if (!read_at(procfd, "oom_score_adj", b, sizeof b, 0) || strcmp(b, "0\n") || !bounds()) return 0;
    return live();
}
static int emit(const struct facts *f, const char *op, int finished) {
    char b[4096];
    int n = snprintf(b, sizeof b,
        "{\"version\":1,\"op\":\"%s\",\"facts\":{\"pid\":\"%s\",\"startTicks\":\"%s\",\"state\":\"%c\",\"membership\":\"0::%s\",\"oomScoreAdj\":\"0\","
        "\"procAnchor\":{\"device\":\"%" PRIu64 "\",\"inode\":\"%" PRIu64 "\"},"
        "\"cgroupRoot\":{\"device\":\"%" PRIu64 "\",\"inode\":\"%" PRIu64 "\",\"fsType\":\"63677270\",\"mountRoot\":\"/\",\"mountPoint\":\"/sys/fs/cgroup\",\"mountDevice\":\"%s\"},"
        "\"observerNamespaces\":{\"pid\":\"%s\",\"cgroup\":\"%s\",\"mount\":\"%s\",\"time\":\"%s\"},"
        "\"bounds\":{\"memoryMax\":\"1073741824\",\"memorySwapMax\":\"0\",\"cpuQuota\":\"100000\",\"cpuPeriod\":\"100000\",\"cpuBurst\":\"0\",\"pidsMax\":\"128\",\"cgroupType\":\"domain\"}}%s}\n",
        op, f->pid, f->ticks, f->state, f->membership, f->proc.dev, f->proc.ino,
        f->cg.dev, f->cg.ino, f->mountdev, f->ns[0], f->ns[1], f->ns[2], f->ns[3],
        finished ? ",\"processStayedAlive\":true" : "");
    return n > 0 && (size_t)n < sizeof b && send_text(b);
}
static int finish_input(void) {
    char b[8]; size_t used = 0;
    while (remaining_ms()) {
        struct pollfd p[2] = {{STDIN_FILENO, POLLIN, 0}, {pidfd, POLLIN, 0}};
        int r = poll(p, 2, remaining_ms());
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0 || p[1].revents || (p[0].revents & (POLLERR | POLLNVAL))) return 0;
        if (!(p[0].revents & POLLIN)) return 0; /* EOF/hangup cancels. */
        ssize_t n = read(STDIN_FILENO, b + used, sizeof b - used);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) return 0;
        used += (size_t)n;
        if (used > 7 || memcmp(b, "finish\n", used)) return 0;
        if (used == 7) {
            /* Reject already-buffered trailing data; caller must send one command. */
            char extra;
            ssize_t x = read(STDIN_FILENO, &extra, 1);
            return x < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && live();
        }
    }
    return 0;
}
int main(int argc, char **argv) {
    int64_t start = now_ns();
    if (start < 0) return 1;
    deadline = start + WINDOW_NS;
    struct stat input_st, output_st;
    /* Private pipe protocol only: do not write to arbitrary filesystem paths. */
    if (fstat(STDIN_FILENO, &input_st) || !S_ISFIFO(input_st.st_mode)
        || fstat(STDOUT_FILENO, &output_st) || !S_ISFIFO(output_st.st_mode)) return 1;
    int flags = fcntl(STDOUT_FILENO, F_GETFL);
    if (flags < 0 || fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK)) return 1;
    uint64_t pidnum; const char *ci = getenv("GITHUB_ACTIONS"), *ci_flag = getenv("CI");
    if (argc != 4 || getuid() == 0 || geteuid() != getuid() || getegid() != getgid()
        || !ci || strcmp(ci, "true") || !ci_flag || strcmp(ci_flag, "true") || !exact_id(argv[1]) || !decimal(argv[2], &pidnum)
        || !pidnum || pidnum > INT_MAX || (strcmp(argv[3], "systemd") && strcmp(argv[3], "cgroupfs"))) return blocked();
    flags = fcntl(STDIN_FILENO, F_GETFL);
    if (flags < 0 || fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK)) return blocked();
    char procpath[64], member[128], device[48], mountid[24];
    (void)snprintf(procpath, sizeof procpath, "/proc/%s", argv[2]);
    procfd = open(procpath, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    selffd = open("/proc/self", O_PATH | O_DIRECTORY | O_CLOEXEC); /* Intentional own reference. */
    if (procfd < 0 || selffd < 0 || !mount_profile(device, mountid)) return blocked();
#ifdef SYS_pidfd_open
    pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pidnum, 0);
#else
    pidfd = -1;
#endif
    if (pidfd < 0 || !live()) return blocked(); /* No unsupported fallback. */
    rootfd = open("/sys/fs/cgroup", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct identity root;
    if (rootfd < 0 || !anchor(rootfd, CGROUP2_MAGIC_P, &root) || !root_mount(mountid)) return blocked();
    char actual[48]; (void)snprintf(actual, sizeof actual, "%u:%u", major((dev_t)root.dev), minor((dev_t)root.dev));
    if (strcmp(actual, device)) return blocked();
    (void)snprintf(member, sizeof member, !strcmp(argv[3], "systemd") ? "/system.slice/docker-%s.scope" : "/docker/%s", argv[1]);
#ifdef SYS_openat2
    struct probe_open_how h = {O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW, 0,
        RESOLVE_BENEATH_P | RESOLVE_NO_SYMLINKS_P | RESOLVE_NO_XDEV_P};
    cgfd = (int)syscall(SYS_openat2, rootfd, member + 1, &h, sizeof h);
#else
    cgfd = -1;
#endif
    struct facts before, after;
    if (cgfd < 0 || !observe(&before, argv[2], member) || !emit(&before, "begun", 0)
        || !finish_input() || !observe(&after, argv[2], member)) return blocked();
    /* States can change R/S/D/I. All other retained facts must remain equal. */
    before.state = after.state;
    if (memcmp(&before, &after, sizeof before) || !live() || !emit(&after, "finished", 1)) return blocked();
    close(cgfd); close(rootfd); close(procfd); close(selffd); close(pidfd);
    return 0;
}
