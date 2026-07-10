/* 01_string_handling.c — log-message formatting module.
 * Realistic pattern: a small embedded logging/formatting helper, the kind of
 * code that shows up in almost every firmware project. Seeded with common
 * string/buffer defects plus a few things that LOOK risky but are actually
 * fine (false-positive traps), so the benchmark measures both recall and
 * precision, not just recall.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_BUF_SIZE 64

static char g_log_buf[LOG_BUF_SIZE];

/* SEEDED: CERT STR31-C — unbounded copy, no length check against dest size. */
void log_set_prefix(const char *prefix)
{
    strcpy(g_log_buf, prefix);
}

/* SEEDED: CERT STR31-C (strcat) — unbounded append onto a fixed buffer. */
void log_append(const char *msg)
{
    strcat(g_log_buf, msg);
}

/* SEEDED: CERT STR31-C (sprintf) + MISRA 21.6 (stdio in production). */
void log_format_reading(int32_t sensor_id, int32_t value)
{
    sprintf(g_log_buf, "sensor %d = %d", sensor_id, value);
    printf("%s\n", g_log_buf);
}

/* NOT a violation (false-positive trap): bounded copy with explicit size and
 * guaranteed termination — a well-written analyzer should not flag this as
 * unbounded, even though it "looks like" strcpy-adjacent code. */
void log_set_prefix_safe(const char *prefix)
{
    size_t n = strlen(prefix);
    if (n >= (size_t)(LOG_BUF_SIZE - 1))
    {
        n = (size_t)(LOG_BUF_SIZE - 1);
    }
    memcpy(g_log_buf, prefix, n);
    g_log_buf[n] = '\0';
}

/* SEEDED: MISRA 21.3 — dynamic allocation not permitted in this class of
 * firmware code. */
char *log_duplicate(const char *src)
{
    char *dup = malloc(LOG_BUF_SIZE);
    if (dup != NULL)
    {
        strcpy(dup, src);
    }
    return dup;
}

/* NOT a violation: no dynamic memory here, just returns a pointer to static
 * storage — a false-positive trap for over-eager "returns pointer" checks. */
const char *log_get_buffer(void)
{
    return g_log_buf;
}
