/* uart_driver.c — companion file to motor_control.c for the fix-loop
 * simulation, giving next_batch() more than one file to group findings by.
 */
#include "fw_types.h"
#include "uart_driver.h"

#define UART_TX_BUF_SIZE 32u

static char g_uart_tx_buf[UART_TX_BUF_SIZE];

/* SEEDED: CERT STR31-C -- unbounded copy onto a fixed buffer. */
void uart_queue_message(const char *msg)
{
    strcpy(g_uart_tx_buf, msg);
}

/* SEEDED: MISRA 15.1 -- goto for error-path cleanup. */
int32_t uart_transmit_all(const uint8_t *data, uint32_t len)
{
    uint32_t i;

    if (data == NULL)
    {
        goto fail;
    }
    for (i = 0u; i < len; i++)
    {
        (void)data[i];
    }
    return 0;

fail:
    return -1;
}

/* SEEDED: MISRA 7.1 -- octal integer constant. */
uint32_t uart_default_baud_index(void)
{
    return 011;
}
