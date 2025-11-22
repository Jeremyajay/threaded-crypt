// Jeremy Cuthbert
// CS333 - Jesse Chaney
// Lab 3 - thread_hash.c

// The purpose of this file is to use PThreads and the crypt() function
// to do a complete a dictionary attack on hashed passwords and see how
// successful we are at cracking those passwords. This program will keep
// track of what kind of encryption the passwords are and the success/failure
// outcome when trying to crack the passwords.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>


/* options */
static char *opt_in = NULL;
static char *opt_dict = NULL;
static char *opt_out = NULL;
static int opt_threads = 1;
static int opt_verbose = 0;
static int opt_nice = 0;

/* data */
static char **hashes = NULL;
static size_t hashes_count = 0;
static char **dict = NULL;
static size_t dict_count = 0;

/* dispatch and output */
static pthread_mutex_t work_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t out_mutex  = PTHREAD_MUTEX_INITIALIZER;
static size_t next_job = 0;
static FILE *out_fp = NULL;

/* per-thread stats */
typedef struct {
    int tid;
    long des;
    long nt;
    long md5;
    long sha256;
    long sha512;
    long yescrypt;
    long gost_yescrypt;
    long bcrypt;
    long total;
    long failed;
    struct timeval start;
    struct timeval end;
} thread_stats_t;

static thread_stats_t *stats = NULL;

/* prototypes */
static void usage(const char *prog);
static char **read_lines(const char *fname, size_t *out_n);
static double timeval_diff(const struct timeval *a, const struct timeval *b);
static void detect_inc(const char *h, thread_stats_t *s);
static char *extract_salt(const char *hash);
static void process_hash(thread_stats_t *ts, size_t idx, struct crypt_data *cdata);
static void *thread_routine(void *arg);

/* usage */
static void usage(const char *prog)
{
    fprintf(stderr,
            "help text\n"
	    "        ./thread_hash ..."
	    "        Options: i:o:d:hvt:n"
            "                -i file         hash file name (required)\n"
            "                -o file         output file name (default stdout)\n"
            "                -d filename     dictionary file name (required)\n"
            "                -t #            number of threads to create (default == 1)\n"
            "                -n              renice to 10\n"
            "                -v              enable verbose mode\n"
            "                -h              helpful text\n",
            prog);
}

/* read lines from a file, strip newlines */
static char **read_lines(const char *fname, size_t *out_n)
{
    FILE *f;
    size_t cap;
    size_t n;
    char **arr;
    char *line;
    size_t len;
    ssize_t r;

    f = fopen(fname, "r");
    if (!f) {
        fprintf(stderr, "error: cannot open %s: %s\n", fname, strerror(errno));
        return NULL;
    }

    cap = 1024;
    n = 0;
    arr = (char **) calloc(cap, sizeof(char *));
    if (!arr) {
        fclose(f);
        return NULL;
    }

    line = NULL;
    len = 0;
    while ((r = getline(&line, &len, f)) != -1) {
        while (r > 0 && (line[r-1] == '\n' || line[r-1] == '\r')) {
            line[--r] = '\0';
        }
        if (r == 0) continue;
        if (n + 1 >= cap) {
            char **tmp;
            cap *= 2;
            tmp = (char **) realloc(arr, cap * sizeof(char *));
            if (!tmp) break;
            arr = tmp;
        }
        arr[n++] = strdup(line);
    }

    free(line);
    fclose(f);
    *out_n = n;
    return arr;
}

/* time difference in seconds */
static double timeval_diff(const struct timeval *a, const struct timeval *b)
{
    double sec;
    sec = (double)(b->tv_sec - a->tv_sec) + (double)(b->tv_usec - a->tv_usec) / 1e6;
    return sec;
}

/* detect hash algorithm and increment counters */
static void detect_inc(const char *h, thread_stats_t *s)
{
    if (!h || h[0] == '\0') return;
    if (h[0] != '$') {
        s->des++;
        return;
    }
    if (h[1] == '3') { s->nt++; return; }
    if (h[1] == '1') { s->md5++; return; }
    if (h[1] == '5') { s->sha256++; return; }
    if (h[1] == '6') { s->sha512++; return; }
    if (h[1] == 'y') { s->yescrypt++; return; }
    if (h[1] == 'g' && h[2] == 'y') { s->gost_yescrypt++; return; }
    if (h[1] == '2' && h[2] == 'b') { s->bcrypt++; return; }
}

/* conservative salt extraction */
static char *extract_salt(const char *hash)
{
    const char *p;
    size_t len;
    char *s;

    if (!hash) return NULL;
    if (hash[0] != '$') {
        size_t L = strlen(hash);
        size_t take = (L >= 2) ? 2 : L;
        s = (char *) malloc(take + 1);
        if (!s) return NULL;
        memcpy(s, hash, take);
        s[take] = '\0';
        return s;
    }

    p = hash;
    while (*p) {
        if (*p == '$') {
            /* count $s until >= 3 */
            /* we'll advance p until third $ field end */
            int dollar = 0;
            const char *q = hash;
            while (*q) {
                if (*q == '$') {
                    dollar++;
                    if (dollar >= 3) {
                        q++;
                        while (*q && *q != '$') q++;
                        p = q;
                        break;
                    }
                }
                q++;
            }
            break;
        }
        p++;
    }

    len = (size_t)(p - hash);
    if (len == 0) len = strlen(hash);
    s = (char *) malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, hash, len);
    s[len] = '\0';
    return s;
}

/* try all dict words for a given hash index */
static void process_hash(thread_stats_t *ts, size_t idx, struct crypt_data *cdata)
{
    const char *hash;
    char *salt;
    int cracked;
    size_t i;

    hash = hashes[idx];
    detect_inc(hash, ts);
    salt = extract_salt(hash);
    cracked = 0;

    for (i = 0; i < dict_count; i++) {
        const char *pw = dict[i];
        char *res;
        res = crypt_r(pw, salt ? salt : "", cdata);
        if (res && strcmp(res, hash) == 0) {
            pthread_mutex_lock(&out_mutex);
            fprintf(out_fp, "cracked  %s  %s\n", pw, hash);
            fflush(out_fp);
            pthread_mutex_unlock(&out_mutex);
            cracked = 1;
            break;
        }
    }

    if (!cracked) {
        pthread_mutex_lock(&out_mutex);
        fprintf(out_fp, "*** failed to crack  %s\n", hash);
        fflush(out_fp);
        pthread_mutex_unlock(&out_mutex);
        ts->failed++;
    }
    ts->total++;
    free(salt);
}

/* thread routine: fetch jobs until none left*/
static void *thread_routine(void *arg)
{
    int tid;
    thread_stats_t *ts;
    struct crypt_data cdata;
    size_t job;

    tid = (int)(intptr_t) arg;
    ts = &stats[tid];

    /* initialize */
    ts->tid = tid;
    ts->des = ts->nt = ts->md5 = ts->sha256 = ts->sha512 = 0;
    ts->yescrypt = ts->gost_yescrypt = ts->bcrypt = 0;
    ts->total = ts->failed = 0;

    memset(&cdata, 0, sizeof(cdata));
    gettimeofday(&ts->start, NULL);

    /* get first job */
    pthread_mutex_lock(&work_mutex);
    job = next_job;
    next_job++;
    pthread_mutex_unlock(&work_mutex);

    while (job < hashes_count) {
        process_hash(ts, job, &cdata);

        /* per-job accounting line to stderr */
        gettimeofday(&ts->end, NULL);
        {
            double elapsed;
            elapsed = timeval_diff(&ts->start, &ts->end);
            fprintf(stderr,
                    "thread: %2d     %.2f sec              DES: %5ld               NT: %5ld              MD5: %5ld           SHA256: %5ld           SHA512: %5ld         YESCRYPT: %5ld    GOST_YESCRYPT: %5ld           BCRYPT: %5ld  total: %8ld  failed: %8ld\n",
                    ts->tid,
                    elapsed,
                    ts->des,
                    ts->nt,
                    ts->md5,
                    ts->sha256,
                    ts->sha512,
                    ts->yescrypt,
                    ts->gost_yescrypt,
                    ts->bcrypt,
                    ts->total,
                    ts->failed);
            fflush(stderr);
        }

        /* fetch next job */
        pthread_mutex_lock(&work_mutex);
        job = next_job;
        next_job++;
        pthread_mutex_unlock(&work_mutex);
    }

    gettimeofday(&ts->end, NULL);
    return NULL;
}

/* main */
int main(int argc, char **argv)
{
    int opt;
    int i;
    pthread_t *tids;
    struct timeval gstart;
    struct timeval gend;
    double total_elapsed;
    long a_des;
    long a_nt;
    long a_md5;
    long a_sha256;
    long a_sha512;
    long a_yes;
    long a_gost;
    long a_bcrypt;
    long a_total;
    long a_failed;

    while ((opt = getopt(argc, argv, "i:o:d:t:vh?n")) != -1) {
        switch (opt) {
        case 'i':
            opt_in = strdup(optarg);
            break;
        case 'o':
            opt_out = strdup(optarg);
            break;
        case 'd':
            opt_dict = strdup(optarg);
            break;
        case 't':
            opt_threads = atoi(optarg);
            if (opt_threads < 1) opt_threads = 1;
            if (opt_threads > 24) opt_threads = 24;
            break;
        case 'v':
            opt_verbose = 1;
            break;
        case 'n':
            opt_nice = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            if (opt == 'h') return 0;
            return 1;
        }
    }

    if (!opt_in || !opt_dict) {
        fprintf(stderr, "error: -i and -d are required\n");
        usage(argv[0]);
        return 2;
    }

    if (opt_nice) {
        if (nice(10) == -1 && errno) {
            if (opt_verbose) fprintf(stderr, "warning: nice failed: %s\n", strerror(errno));
        } else if (opt_verbose) {
            fprintf(stderr, "note: nice(10) applied\n");
        }
    }

    if (opt_out) {
        out_fp = fopen(opt_out, "w");
        if (!out_fp) {
            fprintf(stderr, "error: cannot open %s: %s\n", opt_out, strerror(errno));
            return 3;
        }
    } else {
        out_fp = stdout;
    }

    if (opt_verbose) {
        fprintf(stderr, "verbose: reading hashes from %s\n", opt_in);
        fprintf(stderr, "verbose: reading dict from %s\n", opt_dict);
        fprintf(stderr, "verbose: threads=%d\n", opt_threads);
    }

    hashes = read_lines(opt_in, &hashes_count);
    if (!hashes) return 4;
    dict = read_lines(opt_dict, &dict_count);
    if (!dict) return 5;

    if (opt_verbose) {
        fprintf(stderr, "verbose: loaded %zu hashes, %zu dict words\n", hashes_count, dict_count);
    }

    stats = (thread_stats_t *) calloc(opt_threads, sizeof(thread_stats_t));
    if (!stats) {
        fprintf(stderr, "error: alloc stats\n");
        return 6;
    }

    tids = (pthread_t *) calloc(opt_threads, sizeof(pthread_t));
    if (!tids) {
        fprintf(stderr, "error: alloc tids\n");
        free(stats);
        return 7;
    }

    gettimeofday(&gstart, NULL);

    for (i = 0; i < opt_threads; i++) {
        if (pthread_create(&tids[i], NULL, thread_routine, (void *)(intptr_t)i) != 0) {
            fprintf(stderr, "error: pthread_create failed\n");
            free(tids);
            free(stats);
            return 8;
        }
    }

    for (i = 0; i < opt_threads; i++) {
        pthread_join(tids[i], NULL);
    }

    gettimeofday(&gend, NULL);
    total_elapsed = timeval_diff(&gstart, &gend);

    /* aggregate totals */
    a_des = a_nt = a_md5 = a_sha256 = a_sha512 = a_yes = a_gost = a_bcrypt = 0;
    a_total = a_failed = 0;
    for (i = 0; i < opt_threads; i++) {
        a_des += stats[i].des;
        a_nt += stats[i].nt;
        a_md5 += stats[i].md5;
        a_sha256 += stats[i].sha256;
        a_sha512 += stats[i].sha512;
        a_yes += stats[i].yescrypt;
        a_gost += stats[i].gost_yescrypt;
        a_bcrypt += stats[i].bcrypt;
        a_total += stats[i].total;
        a_failed += stats[i].failed;
    }

    fprintf(stderr,
            "total: %2d      %.2f sec              DES: %5ld               NT: %5ld              MD5: %5ld           SHA256: %5ld           SHA512: %5ld         YESCRYPT: %5ld    GOST_YESCRYPT: %5ld           BCRYPT: %5ld  total: %8ld  failed: %8ld\n",
            opt_threads,
            total_elapsed,
            a_des, a_nt, a_md5, a_sha256, a_sha512, a_yes, a_gost, a_bcrypt, a_total, a_failed);
    fflush(stderr);

    /* cleanup */
    if (out_fp && out_fp != stdout) fclose(out_fp);
    for (i = 0; i < (int)hashes_count; i++) free(hashes[i]);
    free(hashes);
    for (i = 0; i < (int)dict_count; i++) free(dict[i]);
    free(dict);
    free(stats);
    free(tids);
    free(opt_in);
    free(opt_dict);
    if (opt_out) free(opt_out);
    return 0;
}
