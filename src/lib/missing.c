/*
 * turboserve - web server
 * Copyright (c) 2012 L. A. F. Pereira <l@tia.mat.br>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <linux/capability.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "turboserve.h"

#ifndef turboserve_HAVE_MEMPCPY
void *mempcpy(void *dest, const void *src, size_t len)
{
    char *p = memcpy(dest, src, len);
    return p + len;
}
#endif

#ifndef turboserve_HAVE_MEMRCHR
void *memrchr(const void *s, int c, size_t n)
{
    const char *end = (const char *)s + n + 1;
    const char *prev = NULL;

    for (const char *cur = s; cur <= end; prev = cur++) {
        cur = (const char *)memchr(cur, c, (size_t)(end - cur));
        if (!cur)
            break;
    }

    return (void *)prev;
}
#endif

#ifndef turboserve_HAVE_PIPE2
int pipe2(int pipefd[2], int flags)
{
    int r;

    r = pipe(pipefd);
    if (r < 0)
        return r;

    if (fcntl(pipefd[0], F_SETFL, flags) < 0 ||
        fcntl(pipefd[1], F_SETFL, flags) < 0) {
        int saved_errno = errno;

        close(pipefd[0]);
        close(pipefd[1]);

        errno = saved_errno;
        return -1;
    }

    return 0;
}
#endif

#ifndef turboserve_HAVE_ACCEPT4
int accept4(int sock, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    int fd = accept(sock, addr, addrlen);
    int newflags = 0;

    if (fd < 0)
        return fd;

    if (flags & SOCK_NONBLOCK) {
        newflags |= O_NONBLOCK;
        flags &= ~SOCK_NONBLOCK;
    }
    if (flags & SOCK_CLOEXEC) {
        newflags |= O_CLOEXEC;
        flags &= ~SOCK_CLOEXEC;
    }
    if (flags) {
        errno = -EINVAL;
        return -1;
    }

    if (fcntl(fd, F_SETFL, newflags) < 0) {
        int saved_errno = errno;

        close(fd);

        errno = saved_errno;
        return -1;
    }

    return fd;
}
#endif

#ifndef turboserve_HAVE_CLOCK_GETTIME
int clock_gettime(clockid_t clk_id, struct timespec *ts)
{
    switch (clk_id) {
    case CLOCK_MONOTONIC:
    case CLOCK_MONOTONIC_COARSE:
        /* FIXME: time() isn't monotonic */
        ts->tv_sec = time(NULL);
        ts->tv_nsec = 0;
        return 0;
    }

    errno = EINVAL;
    return -1;
}
#endif

#if defined(__linux__) || defined(__CYGWIN__)
#if defined(turboserve_HAVE_GETAUXVAL)
#include <sys/auxv.h>
#endif

int proc_pidpath(pid_t pid, void *buffer, size_t buffersize)
{
    ssize_t path_len;

    if (getpid() != pid) {
        errno = EACCES;

        return -1;
    }

#if defined(turboserve_HAVE_GETAUXVAL)
    const char *execfn = (const char *)getauxval(AT_EXECFN);

    if (execfn) {
        size_t len = strlen(execfn);

        if (len + 1 < buffersize) {
            memcpy(buffer, execfn, len + 1);

            return 0;
        }
    }
#endif

    path_len = readlink("/proc/self/exe", buffer, buffersize);
    if (path_len < 0)
        return -1;

    if (path_len < (ssize_t)buffersize) {
        ((char *)buffer)[path_len] = '\0';

        return 0;
    }

    errno = EOVERFLOW;
    return -1;
}

#elif defined(__FreeBSD__)
#include <sys/sysctl.h>

int proc_pidpath(pid_t pid, void *buffer, size_t buffersize)
{
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
    size_t path_len = buffersize;

    if (getpid() != pid) {
        errno = EACCES;

        return -1;
    }

    if (sysctl(mib, N_ELEMENTS(mib), buffer, &path_len, NULL, 0) < 0)
        return -1;

    return 0;
}
#elif defined(turboserve_HAVE_DLADDR) && !defined(__APPLE__)
#include <dlfcn.h>

int proc_pidpath(pid_t pid, void *buffer, size_t buffersize)
{
    Dl_info info;

    if (getpid() != pid) {
        errno = EACCES;
        return -1;
    }

    extern int main();
    if (dladdr(main, &info)) {
        if (!info.dli_fname)
            goto fallback;

        if (buffersize < PATH_MAX - 1)
            goto fallback;

        if (realpath(info.dli_fname, buffer))
            return 0;
    }

fallback:
    if (strlcpy(buffer, "turboserve", buffersize) >= buffersize) {
        errno = ENOMEM;
        return -1;
    }

    return 0;
}
#elif !defined(__APPLE__)
#error proc_pidpath() not implemented for this architecture
#endif

#if defined(__linux__)

#if !defined(turboserve_HAVE_GETTID)
#include <sys/syscall.h>

pid_t gettid(void) { return (pid_t)syscall(SYS_gettid); }
#endif

#elif defined(__FreeBSD__)
#include <sys/thr.h>

pid_t gettid(void)
{
    long ret;

    thr_self(&ret);

    return (pid_t)ret;
}
#elif defined(__APPLE__) && MAC_OS_X_VERSION_MAX_ALLOWED >= 101200
#include <sys/syscall.h>

pid_t gettid(void) { return syscall(SYS_thread_selfid); }
#else
pid_t gettid(void) { return (pid_t)pthread_self(); }
#endif

#if defined(__APPLE__)
/* NOTE: Although saved UID/GID cannot be set using sysctl(), for the use
 * case in turboserve, it's possible to obtain the value and check if they're the
 * ones expected -- and abort if it's not.  Should be good enough for a
 * wrapper like this.  */

#include <sys/sysctl.h>

static int get_current_proc_info(struct kinfo_proc *kp)
{
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t len = sizeof(*kp);

    return sysctl(mib, N_ELEMENTS(mib), kp, &len, NULL, 0);
}

int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    struct kinfo_proc kp;

    if (!get_current_proc_info(&kp)) {
        *ruid = getuid();
        *euid = geteuid();
        *suid = kp.kp_eproc.e_pcred.p_svuid;

        return 0;
    }

    return -1;
}

int setresuid(uid_t ruid, uid_t euid, uid_t suid __attribute__((unused)))
{
    return setreuid(ruid, euid);
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid __attribute__((unused)))
{
    return setregid(rgid, egid);
}

int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
    struct kinfo_proc kp;

    if (!get_current_proc_info(&kp)) {
        *rgid = getgid();
        *egid = getegid();
        *sgid = kp.kp_eproc.e_pcred.p_svgid;

        return 0;
    }

    return -1;
}
#endif

#if !defined(turboserve_HAVE_MKOSTEMP)
int mkostemp(char *tmpl, int flags)
{
    int fd, fl;

    fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;

    fl = fcntl(fd, F_GETFD);
    if (fl < 0)
        goto out;

    if (flags & O_CLOEXEC)
        fl |= FD_CLOEXEC;

    if (fcntl(fd, F_SETFD, fl) < 0)
        goto out;

    return fd;

out:
    close(fd);
    return -1;
}
#endif

#if !defined(turboserve_HAVE_REALLOCARRAY)
/*	$OpenBSD: reallocarray.c,v 1.2 2014/12/08 03:45:00 bcook Exp $	*/
/*
 * Copyright (c) 2008 Otto Moerbeek <otto@drijf.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#if !defined(turboserve_HAVE_BUILTIN_MUL_OVERFLOW)
/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW ((size_t)1 << (sizeof(size_t) * 4))

static inline bool umull_overflow(size_t a, size_t b, size_t *out)
{
    if ((a >= MUL_NO_OVERFLOW || b >= MUL_NO_OVERFLOW) && a > 0 &&
        SIZE_MAX / a < b)
        return true;
    *out = a * b;
    return false;
}
#else
#define umull_overflow __builtin_mul_overflow
#endif

void *reallocarray(void *optr, size_t nmemb, size_t size)
{
    size_t total_size;
    if (UNLIKELY(umull_overflow(nmemb, size, &total_size))) {
        errno = ENOMEM;
        return NULL;
    }
    if (UNLIKELY(total_size == 0)) {
        free(optr);
        return malloc(1);
    }
    return realloc(optr, total_size);
}
#endif /* turboserve_HAVE_REALLOCARRAY */

#if !defined(turboserve_HAVE_READAHEAD)
ssize_t readahead(int fd, off_t offset, size_t count)
{
#if defined(turboserve_HAVE_POSIX_FADVISE)
    return (ssize_t)posix_fadvise(fd, offset, (off_t)count,
                                  POSIX_FADV_WILLNEED);
#else
    (void)fd;
    (void)offset;
    (void)count;

    return 0;
#endif
}
#endif

#if !defined(turboserve_HAVE_GET_CURRENT_DIR_NAME)
#include <limits.h>

char *get_current_dir_name(void)
{
    char buffer[PATH_MAX];
    char *ret;

    ret = getcwd(buffer, sizeof(buffer));
    return strdup(ret ? ret : "/");
}
#endif

#ifndef __linux__
int capset(struct __user_cap_header_struct *header,
           struct __user_cap_data_struct *data)
{
#ifdef __OpenBSD__
    if (header->version != _LINUX_CAPABILITY_VERSION_1)
        return -EINVAL;
    if (header->pid != 0)
        return -EINVAL;
    if (data->effective == 0 && data->permitted == 0)
        return pledge("stdio rpath tmppath inet error", NULL);
#else
    (void)header;
    (void)data;
#endif

    return 0;
}
#endif

#if !defined(turboserve_HAVE_FWRITE_UNLOCKED)
size_t fwrite_unlocked(const void *ptr, size_t size, size_t n, FILE *stream)
{
    size_t to_write = size * n;
    const size_t total_to_write = to_write;

    if (!to_write)
        return 0;

    fflush/* _unlocked? */(stream);

    while (to_write) {
        ssize_t r = write(fileno(stream), ptr, to_write);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        to_write -= (size_t)r;
    }

    return (total_to_write - to_write) / size;
}
#endif

#if !defined(turboserve_HAVE_STATFS)
int statfs(const char *path, struct statfs *buf)
{
    (void)path;
    (void)buf;

    *errno = ENOSYS;
    return -1;
}
#endif

static int turboserve_getentropy_fallback(void *buffer, size_t buffer_len)
{
    int fd;

    fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY);
    if (fd < 0) {
        fd = open("/dev/random", O_CLOEXEC | O_RDONLY);
        if (fd < 0)
            return -1;
    }
    ssize_t total_read = read(fd, buffer, buffer_len);
    close(fd);

    return total_read == (ssize_t)buffer_len ? 0 : -1;
}

#if defined(SYS_getrandom)
long int turboserve_getentropy(void *buffer, size_t buffer_len, int flags)
{
    long r = syscall(SYS_getrandom, buffer, buffer_len, flags);

    if (r < 0)
        return turboserve_getentropy_fallback(buffer, buffer_len);

    return r;
}
#elif defined(turboserve_HAVE_GETENTROPY)
long int turboserve_getentropy(void *buffer, size_t buffer_len, int flags)
{
    (void)flags;

    if (!getentropy(buffer, buffer_len))
        return 0;

    return turboserve_getentropy_fallback(buffer, buffer_len);
}
#else
long int turboserve_getentropy(void *buffer, size_t buffer_len, int flags)
{
    (void)flags;
    return turboserve_getentropy_fallback(buffer, buffer_len);
}
#endif

static inline int isalpha_neutral(char c)
{
    /* Use this instead of isalpha() from ctype.h because they consider
     * the current locale.  This assumes CHAR_BIT == 8.  */
    static const unsigned char table[32] = {
        0, 0, 0, 0, 0, 0, 0, 0, 254, 255, 255, 7, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,   0,   0,   0, 0, 0, 0, 0,
    };
    unsigned char uc = (unsigned char)c;
    return table[uc >> 3] & 1 << (uc & 7);
}

bool strcaseequal_neutral_len(const char *a, const char *b, size_t len)
{
    while (len--) {
        char ca = *a++;
        char cb = *b++;

        /* See which bits are different in either character */
        switch (ca ^ cb) {
        case 0: /* ca and cb are the same: advance */
            if (ca == '\0') {
                /* If `ca` is 0 here, then cb must be 0 too, so we don't
                 * need to check both.  */
                return true;
            }
            continue;
        case 32: /* Only 5th bit is set: advance if either are uppercase
                  * ASCII characters, but differ in case only */
            /* If either is an uppercase ASCII character, then move on */
            if (isalpha_neutral(ca) || isalpha_neutral(cb))
                continue;
            /* Fallthrough */
        default:
            return false;
        }
    }

    assert((ssize_t)len < 0);
    return true;
}

ALWAYS_INLINE bool strcaseequal_neutral(const char *a, const char *b)
{
    return strcaseequal_neutral_len(a, b, SIZE_MAX);
}

turboserve_SELF_TEST(strcaseequal_neutral)
{
    assert(strcaseequal_neutral("turboserve", "turboserve") == true);
    assert(strcaseequal_neutral("turboserve", "turboserve") == true);
    assert(strcaseequal_neutral("SomE-HeaDer", "some-header") == true);

    assert(strcaseequal_neutral("SomE-HeaDeP", "some-header") == false);
    assert(strcaseequal_neutral("turboserve", "lwam") == false);
    assert(strcaseequal_neutral("turboserve", "lWaM") == false);

    assert(strcaseequal_neutral_len("Host: localhost:8080", "Host", 4) == true);
    assert(strcaseequal_neutral_len("Host", "Host: localhost:8080", 4) == true);
    assert(strcaseequal_neutral_len("Host", "Hosh: not-localhost:1234", 4) == false);
    assert(strcaseequal_neutral_len("Host: something-else:443", "Host: localhost:8080", 4) == true);

    static_assert(CHAR_BIT == 8, "sane CHAR_BIT value");
    static_assert('*' == 42, "ASCII character set");
    static_assert('0' == 48, "ASCII character set");
    static_assert('a' == 97, "ASCII character set");
}

#ifndef turboserve_HAVE_STPCPY
char *stpncpy(char *restrict dst, const char *restrict src, size_t sz)
{
    /* Implementation from the Linux stpcpy(3) man page. */
    char *p = mempcpy(dst, src, sz);
    *p = 0;
    return p;
}

char *stpcpy(char *restrict dst, const char *restrict src)
{
    return stpncpy(dst, src, strlen(src));
}
#endif
