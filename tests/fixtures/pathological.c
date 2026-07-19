/* Shapes of real C that have broken native detectors, concentrated into one
 * file. Every construct here is legal, idiomatic, and was extracted from a
 * false positive found on the benchmark corpus (littlefs, lwip, mbedtls,
 * zephyr) AFTER the detector's own unit tests passed.
 *
 * The point: hand-written fixtures are clean by construction, which is what
 * makes them readable and also what makes them useless for finding these.
 * A new detector runs against this file first, in milliseconds, instead of
 * discovering the same shapes a corpus run later.
 *
 * NOTHING in this file is a violation of the rules listed beside it. Any
 * finding here is a false positive.
 */

#include <stdint.h>

static int debug_level;

/* --- multi-line macro: body lines do not start with '#' (broke 20.1) ----- */
#define WIDE_MACRO(a, b) \
    do {                 \
        (a) = (b);       \
    } while (0)

/* A conditional include after a multi-line macro is still compliant. */
#include <stddef.h>

/* --- continuation line that DOES open with '#' (broke 20.13) ------------- */
#define READ_SYSREG(op1, CRn, CRm)                    \
    __asm__ volatile("mrc " #op1 ", "                 \
    #CRm : "=r" (val) :: "memory")

/* --- two-step token paste: not a stringize-then-paste (broke 20.11) ------ */
#define FN_FROM_ASN1(NAME) oid_ ## NAME ## _from_asn1

/* --- '#' inside a string literal is not an operator (guards 20.10) ------- */
#define PROMPT_STRING "# "

/* --- header names: forward slashes are compliant (guards 20.2) ----------- */
#include <sys/types.h>

/* --- code and #include in OPPOSITE branches (broke 20.1) ----------------- */
#if defined(_WIN32)
static int wsa_init_done = 0;
#else
#include <unistd.h>
#endif

/* --- C++-only linkage block is not code in a C TU (broke 20.1) ---------- */
#ifdef __cplusplus
extern "C" {
#endif
#include <string.h>
#ifdef __cplusplus
}
#endif

/* --- multi-line function signature (broke 15.2) -------------------------- */
static int parse_thing(const unsigned char **p,
                       const unsigned char *end,
                       size_t *len)
{
    int ret = 0;
    if (p == NULL) {
        goto out;              /* forward jump, compliant */
    }
    ret = 1;
out:
    return ret;
}

/* A second function with its OWN 'out:' label. Labels are function-scoped,
 * so this goto is forward too -- resolving it against the label above is the
 * bug that produced 423 findings in mbedtls. */
static int parse_other(const unsigned char **p,
                       const unsigned char *end)
{
    int ret = 0;
    if (end == NULL) {
        goto out;              /* forward jump, compliant */
    }
    ret = 1;
out:
    return ret;
}

/* --- one-line function definition (broke 17.2) --------------------------- */
/* The body opens and closes on the signature's own line, so the line nets to
 * zero braces. A frame recorded at the end-of-line depth can never close, and
 * absorbs the rest of the file -- making every later call to this function
 * look like recursion. lwip's test suite is full of these. */
static void set_debug(int a) { debug_level = a; }

static void calls_it_twice(void)
{
    set_debug(1);              /* not recursion: a different function */
    set_debug(0);
}

/* --- switch: label with a brace on its own line (broke 16.2 / 16.6) ------ */
void switch_shapes(int v)
{
    switch (v) {
        case 1: {              /* brace on the label line */
            WIDE_MACRO(v, 1);
            break;
        }
        case 2:
        case 3:                /* shared labels: an empty clause is permitted */
            WIDE_MACRO(v, 2);
            break;
#if defined(FEATURE_X)
        case 4:
            break;
#endif                         /* directives between clauses (broke 16.3) */
        default:
            break;
    }
}

/* --- clause ending in a noreturn call (broke 16.3) ----------------------- */
void clause_with_noreturn(int v)
{
    switch (v) {
        case 1:
            WIDE_MACRO(v, 1);
            break;
        case 2:
            WIDE_MACRO(v, 2);
            break;
        default:
            break;
    }
}

/* --- sizeof on a real array vs an array parameter (guards 12.5) ---------- */
unsigned long elem_size(int a[10])
{
    return sizeof(a[0]);       /* element size: compliant */
}

/* --- subscript that merely starts with 'static' (guards 17.6) ------------ */
void subscript_shape(int *buf, int static_offset)
{
    buf[static_offset] = 0;
}
