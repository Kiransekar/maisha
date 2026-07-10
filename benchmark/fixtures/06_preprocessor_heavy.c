/* 06_preprocessor_heavy.c — feature-flagged sensor pipeline.
 * Realistic pattern: heavy #ifdef/#if feature gating is endemic to shared
 * embedded codebases (one source tree, many product variants). This is a
 * targeted regression fixture for the MISRA 15.6 preprocessor-blindness fix
 * (see CHANGELOG "Unreleased") at realistic scale, not just the minimal unit
 * test already in tests/test_benchmark_fixes.py.
 */
#include <stdint.h>

#define FEATURE_FILTER 1
#define FEATURE_LOGGING 0

/* NOT a violation: the if-header's body IS braced — the brace just sits on
 * the far side of a feature-flag block. This is the exact FreeRTOS-derived
 * false-positive pattern the fix targets. */
int32_t apply_filter(int32_t raw_value)
{
    int32_t filtered;

    if (raw_value < 0)
#if FEATURE_FILTER
    {
        filtered = 0;
    }
#else
    {
        filtered = raw_value;
    }
#endif
    else
    {
        filtered = raw_value;
    }

    return filtered;
}

/* NOT a violation: same pattern with #ifdef/#endif instead of #if/#else, and
 * a #undef in between the check and its result — must not itself be flagged
 * as anything with the header/body brace check confused by the noise. */
int32_t clamp_reading(int32_t value, int32_t max_value)
{
    int32_t clamped = value;

    if (value > max_value)
#ifdef FEATURE_FILTER
#undef FEATURE_FILTER
    {
        clamped = max_value;
    }
#endif

    return clamped;
}

/* SEEDED: MISRA 15.6 — genuine braceless body, positioned right after the
 * preprocessor noise above, so the analyzer must tell the two apart rather
 * than either over- or under-suppressing near #if blocks. */
int32_t saturate_reading(int32_t value, int32_t floor_value)
{
    if (value < floor_value)
        value = floor_value;

    return value;
}

/* NOT a violation: #undef of a *local* macro the module itself defined and
 * is done with — MISRA 20.5 nominally flags any #undef, so this is a
 * SEEDED expectation (rule fires), not a false-positive trap; listed here
 * for clarity that the rule is intentionally broad. */
#define LOCAL_SCRATCH_SIZE 8
#undef LOCAL_SCRATCH_SIZE

#if FEATURE_LOGGING
void log_pipeline_stage(int32_t stage)
{
    (void)stage;
}
#endif
