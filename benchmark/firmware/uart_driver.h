#ifndef UART_DRIVER_H
#define UART_DRIVER_H
#include "fw_types.h"

void uart_queue_message(const char *msg);
int32_t uart_transmit_all(const uint8_t *data, uint32_t len);
uint32_t uart_default_baud_index(void);

#endif
