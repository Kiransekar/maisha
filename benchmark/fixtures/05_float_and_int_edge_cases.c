/* 05_float_and_int_edge_cases.c — numeric edge-case handling.
 * Realistic pattern: sensor scaling and threshold comparisons, exactly the
 * class of code where semantic-risk fixes (casts, sign conversions) are most
 * dangerous — see README's "verification gate" worked example. This fixture
 * targets detection accuracy for the numeric rule family, not the fix loop
 * (the fix loop / verification-gate behavior is exercised separately against
 * the synthetic firmware module).
 */
#include <stdint.h>

/* SEEDED: CERT FLP37-C — floating-point equality comparison. */
int32_t ratio_is_half(double ratio)
{
    if (ratio == 0.5)
    {
        return 1;
    }
    return 0;
}

/* SEEDED: CERT FLP37-C (second, independent instance — inequality form). */
int32_t reading_is_zeroed(float reading)
{
    if (reading != 0.0f)
    {
        return 0;
    }
    return 1;
}

/* SEEDED: MISRA 7.3 — lowercase 'l' integer suffix, easily misread as '1'. */
uint32_t max_sample_count(void)
{
    return 100000ul;
}

/* NOT a violation: a normal, safe unsigned comparison against a named
 * constant — false-positive trap for a naive "any comparison with a cast
 * nearby" heuristic. */
int32_t within_bounds(uint32_t value, uint32_t limit)
{
    if (value <= limit)
    {
        return 1;
    }
    return 0;
}

/* SEEDED (documentation/behavioral case, not necessarily native-detected):
 * the exact sentinel-cast trap from the README. threshold == -1 means
 * "no limit configured"; casting it to unsigned before comparing turns "no
 * limit" into "the largest possible limit" for sensor_val > threshold. A
 * rescan-only verification policy would mark this "fixed" the moment the
 * cast silences a signed/unsigned comparison warning — which is exactly
 * backwards. This function is intentionally already in the "fixed but
 * wrong" state so the benchmark can check whether Maisha's semantic-risk
 * classifier recognizes the cast as high-risk regardless. */
void check_shutdown_threshold(int32_t threshold, uint32_t sensor_val)
{
    if (sensor_val > (uint32_t)threshold)
    {
        /* trigger_shutdown(); -- omitted, fixture only needs the comparison */
    }
}
