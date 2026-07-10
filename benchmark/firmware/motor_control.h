#ifndef MOTOR_CONTROL_H
#define MOTOR_CONTROL_H
#include "fw_types.h"

extern int32_t g_configured_current_limit_ma;

int32_t motor_should_shutdown(uint32_t sensor_val_ma);
uint32_t motor_speed_for_mode(int32_t mode);
void motor_apply_ramp_limit(int32_t *requested_speed, int32_t max_delta);
int32_t motor_duty_cycle_is_full(float duty);

#endif
