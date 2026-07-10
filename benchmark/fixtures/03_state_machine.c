/* 03_state_machine.c — event-driven state machine for a door-lock controller.
 * Realistic pattern: mostly well-structured control code with long function
 * signatures (common in event-dispatch APIs), a genuine recursive helper, and
 * a same-named-function trap that used to trigger Maisha's MISRA 17.2 false
 * positive (see BENCHMARKS.md / CHANGELOG "Unreleased" fix). This file is
 * intentionally MOSTLY clean, to test precision on realistic (not
 * deliberately terrible) code, with a small number of seeded defects.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum
{
    LOCK_STATE_LOCKED = 0,
    LOCK_STATE_UNLOCKED,
    LOCK_STATE_ALARM
} lock_state_t;

typedef struct
{
    lock_state_t state;
    uint32_t     retry_count;
} lock_context_t;

/* Genuine direct recursion (not a violation to detect correctly is the point
 * — SEEDED expectation: MISRA 17.2 SHOULD fire here). Bounded by depth so
 * it's not runaway, but MISRA 17.2 is about avoiding recursion outright on
 * safety-critical targets (stack budget), regardless of boundedness. */
static uint32_t retry_backoff_ms(uint32_t attempt)
{
    if (attempt == 0u)
    {
        return 50u;
    }
    return 2u * retry_backoff_ms(attempt - 1u);
}

/* A different, unrelated function that legitimately CALLS retry_backoff_ms.
 * This is the exact shape of the old false-positive: a call from inside a
 * function with a long, wrapped signature to a function defined earlier in
 * the file. NOT a violation — must NOT be flagged as recursion. */
static uint32_t compute_next_retry_delay_ms( const lock_context_t *ctx,
                                              uint32_t              base_delay_ms )
{
    uint32_t delay = retry_backoff_ms(ctx->retry_count);
    return delay + base_delay_ms;
}

/* NOT a violation: a normal bounded for-loop, no recursion, no missing
 * braces, no banned calls — a false-positive trap for over-eager heuristics
 * that might fire on any function containing a call to something with a
 * similar-sounding name. */
static bool lock_context_is_valid(const lock_context_t *ctx)
{
    bool ok = true;
    uint32_t i;

    for (i = 0u; i < 4u; i++)
    {
        if (ctx == NULL)
        {
            ok = false;
            break;
        }
    }
    return ok;
}

/* SEEDED: MISRA 15.6 — braceless if body (single seeded defect in this
 * otherwise well-braced file, to test precision doesn't drown in noise). */
lock_state_t lock_handle_event(lock_context_t *ctx, int32_t event)
{
    if (!lock_context_is_valid(ctx))
        return LOCK_STATE_ALARM;

    if (event == 1)
    {
        ctx->state = LOCK_STATE_UNLOCKED;
        ctx->retry_count = 0u;
    }
    else if (event == 2)
    {
        ctx->retry_count++;
        if (ctx->retry_count > 3u)
        {
            ctx->state = LOCK_STATE_ALARM;
        }
    }
    else
    {
        ctx->state = LOCK_STATE_LOCKED;
    }

    return ctx->state;
}
