/* motor_control.c — motor speed control with an over-current shutdown.
 * This file exists to drive Maisha's engineered fix loop end-to-end (begin
 * -> next_batch -> fix -> record_attempt -> verify -> converge), including
 * the exact "sentinel cast" scenario from the README's verification-gate
 * worked example. See benchmark/run_loop_simulation.py.
 */
#include "fw_types.h"
#include "motor_control.h"

#define MOTOR_MAX_CURRENT_MA 4000u

/* threshold_ma == -1 is the sentinel for "no configured limit" (feature not
 * provisioned yet on this hardware variant). This is intentionally signed
 * so "no limit" can be represented distinctly from "limit of zero". */
int32_t g_configured_current_limit_ma = -1;

/* SEEDED: MISRA 10.x / CERT INT31-C territory -- implicit signed/unsigned
 * comparison between threshold (signed, sentinel-bearing) and sensor_val
 * (unsigned). This is the finding the fix-loop simulation will "fix" with
 * the exact wrong cast from the README, to prove the verification gate
 * catches it. */
int32_t motor_should_shutdown(uint32_t sensor_val_ma)
{
    int32_t threshold = g_configured_current_limit_ma;

    if (sensor_val_ma > threshold)
    {
        return 1;
    }
    return 0;
}

/* SEEDED: MISRA 16.4 -- switch without default. */
uint32_t motor_speed_for_mode(int32_t mode)
{
    uint32_t speed;

    switch (mode)
    {
        case 0:
            speed = 0u;
            break;
        case 1:
            speed = 500u;
            break;
        case 2:
            speed = 1000u;
            break;
    }

    return speed;
}

/* SEEDED: MISRA 15.6 -- braceless if body. */
void motor_apply_ramp_limit(int32_t *requested_speed, int32_t max_delta)
{
    if (*requested_speed > max_delta)
        *requested_speed = max_delta;
}

/* SEEDED: CERT FLP37-C -- floating point equality. */
int32_t motor_duty_cycle_is_full(float duty)
{
    if (duty == 1.0f)
    {
        return 1;
    }
    return 0;
}
