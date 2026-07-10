/* 04_memory_and_signals.c — a deliberately library-heavy module exercising
 * the "banned function" rule family (MISRA 21.x / CERT). Realistic pattern:
 * this is the kind of legacy C a team inherits from a non-embedded codebase
 * and needs to triage wholesale before it's fit for a safety-critical target.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>

static jmp_buf g_recovery_point;

/* SEEDED: MISRA 21.4 — setjmp/longjmp (non-local jump), x2 (setjmp + longjmp
 * are separate BANNED_CALLS entries, both should fire). */
void install_recovery_point(void)
{
    if (setjmp(g_recovery_point) != 0)
    {
        return;
    }
}

void trigger_recovery(void)
{
    longjmp(g_recovery_point, 1);
}

/* SEEDED: MISRA 21.5 — signal handling (signal + raise). */
static void on_fault(int sig)
{
    (void)sig;
    trigger_recovery();
}

void install_fault_handler(void)
{
    signal(11, on_fault);
}

void self_test_fault_path(void)
{
    raise(11);
}

/* SEEDED: MISRA 21.3 (malloc/free) + CERT MEM-family risk via a config
 * parser that allocates a scratch buffer per call — realistic but wrong for
 * a safety-critical target with no heap. */
char *config_parse_token(const char *raw)
{
    char *scratch = malloc(32);
    if (scratch == NULL)
    {
        return NULL;
    }
    strncpy(scratch, raw, 31);
    scratch[31] = '\0';
    return scratch;
}

void config_release_token(char *token)
{
    free(token);
}

/* SEEDED: CERT ERR34-C — atoi gives no error detection (also MISRA 21.7
 * territory, not in this KB's curated set, but atoi itself is directly
 * covered). */
int32_t config_parse_int(const char *raw)
{
    return (int32_t)atoi(raw);
}

/* SEEDED: CERT CON33-C — strtok has static internal state, not
 * reentrant/thread-safe. */
const char *config_next_field(char *line)
{
    return strtok(line, ",");
}

/* SEEDED: CERT MSC32-C — rand() is a weak PRNG, unsuitable for anything
 * security-sensitive (nonces, session tokens, jitter that must not be
 * predictable). */
uint32_t config_random_backoff(void)
{
    return (uint32_t)rand() % 100u;
}

/* SEEDED: CERT ENV33-C / MISRA 21.8 — system() invokes a command processor. */
void config_run_diagnostics(void)
{
    system("diag --self-test");
}

/* SEEDED: MISRA 21.9 — qsort is a library sort that MAY recurse internally
 * (implementation-defined stack usage), disallowed on this class of target. */
static int cmp_int(const void *a, const void *b)
{
    return (*(const int32_t *)a) - (*(const int32_t *)b);
}

void config_sort_priorities(int32_t *arr, size_t n)
{
    qsort(arr, n, sizeof(int32_t), cmp_int);
}
