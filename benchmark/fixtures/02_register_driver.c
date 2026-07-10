/* 02_register_driver.c — memory-mapped peripheral driver.
 * Realistic pattern: direct register access, a status union for a hardware
 * overlay, and an error-handling path using goto (common in driver code that
 * needs single-exit cleanup). Mix of real MISRA violations and legitimate
 * hardware-driver idioms that should NOT be over-flagged.
 */
#include <stdint.h>

#define UART_BASE_ADDR   ((uint32_t)0x40011000u)
#define UART_STATUS_TXE  ((uint32_t)0x00000080u)

/* SEEDED: MISRA 19.2 — union declaration (deliberate hardware overlay; a
 * real project would carry a deviation record for this, but the raw scan
 * must still surface it). */
typedef union
{
    uint32_t raw;
    struct
    {
        uint32_t enable : 1;
        uint32_t mode   : 2;
        uint32_t reserved : 29;
    } bits;
} uart_ctrl_t;

static volatile uint32_t * const uart_status_reg = (volatile uint32_t *)(UART_BASE_ADDR + 0x00u);
static volatile uint32_t * const uart_data_reg   = (volatile uint32_t *)(UART_BASE_ADDR + 0x04u);

/* SEEDED: MISRA Dir 4.6 — basic numeric type ("int") instead of a
 * fixed-width <stdint.h> type. */
int uart_last_error;

/* NOT a violation: pointer arithmetic here is a false-positive trap for a
 * naive "any + on a pointer" rule — MISRA 18.4 only applies to pointer
 * arithmetic on *objects*, and register-bank indexing by a constant offset
 * on a peripheral base address is standard driver practice. A precise
 * analyzer may still flag it (advisory, not incorrect), so this is tracked
 * as an acceptable/expected advisory rather than a hard false positive. */
static volatile uint32_t *uart_reg_at(uint32_t offset)
{
    return (volatile uint32_t *)(UART_BASE_ADDR + offset);
}

/* SEEDED: MISRA 15.1 — goto used for error-path cleanup. */
int uart_send_byte(uint8_t byte)
{
    int32_t timeout = 100000;

    while (((*uart_status_reg) & UART_STATUS_TXE) == 0u)
    {
        timeout--;
        if (timeout <= 0)
        {
            goto fail;
        }
    }
    *uart_data_reg = (uint32_t)byte;
    return 0;

fail:
    uart_last_error = 1;
    return -1;
}

/* SEEDED: MISRA 16.4 — switch statement with no default label. */
void uart_configure(uart_ctrl_t *ctrl, int32_t mode)
{
    switch (mode)
    {
        case 0:
            ctrl->bits.mode = 0u;
            break;
        case 1:
            ctrl->bits.mode = 1u;
            break;
        case 2:
            ctrl->bits.mode = 2u;
            break;
    }
    ctrl->bits.enable = 1u;
}

/* SEEDED: MISRA 7.1 (octal constant) + MISRA 13.4 (assignment in condition). */
int uart_self_test(void)
{
    int32_t mask = 010;
    int32_t result;

    if (result = mask)
    {
        return result;
    }
    return 0;
}
