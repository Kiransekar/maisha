/* 07_clean_reference.c — a deliberately well-written reference module.
 * Purpose: measure the false-positive rate on GOOD code. Every pattern here
 * follows the practices the other fixtures' seeded bugs violate: fixed-width
 * types throughout, bounded string operations, no dynamic memory, no banned
 * library calls, always-braced control flow, exhaustive switches, no
 * recursion, no float equality, tabs/line-length kept in bounds. Expected
 * result: zero substantive findings. Any finding here is either a genuine
 * false positive or a defect in this fixture that must be fixed, not waved
 * through.
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define RING_BUFFER_CAPACITY 16u

typedef struct
{
    uint8_t  data[RING_BUFFER_CAPACITY];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
} ring_buffer_t;

void ring_buffer_init(ring_buffer_t *rb)
{
    (void)memset(rb->data, 0, sizeof(rb->data));
    rb->head = 0u;
    rb->tail = 0u;
    rb->count = 0u;
}

bool ring_buffer_push(ring_buffer_t *rb, uint8_t value)
{
    bool accepted;

    if (rb->count >= RING_BUFFER_CAPACITY)
    {
        accepted = false;
    }
    else
    {
        rb->data[rb->head] = value;
        rb->head = (rb->head + 1u) % RING_BUFFER_CAPACITY;
        rb->count++;
        accepted = true;
    }

    return accepted;
}

bool ring_buffer_pop(ring_buffer_t *rb, uint8_t *out_value)
{
    bool available;

    if (rb->count == 0u)
    {
        available = false;
    }
    else
    {
        *out_value = rb->data[rb->tail];
        rb->tail = (rb->tail + 1u) % RING_BUFFER_CAPACITY;
        rb->count--;
        available = true;
    }

    return available;
}

uint32_t ring_buffer_len(const ring_buffer_t *rb)
{
    return rb->count;
}

typedef enum
{
    COPY_STATUS_OK = 0,
    COPY_STATUS_TRUNCATED,
    COPY_STATUS_NULL_INPUT
} copy_status_t;

copy_status_t bounded_string_copy(char *dest, uint32_t dest_size,
                                   const char *src)
{
    copy_status_t status;
    uint32_t src_len;
    uint32_t copy_len;

    if ((dest == NULL) || (src == NULL) || (dest_size == 0u))
    {
        status = COPY_STATUS_NULL_INPUT;
    }
    else
    {
        src_len = (uint32_t)strlen(src);
        copy_len = src_len;
        if (copy_len > (dest_size - 1u))
        {
            copy_len = dest_size - 1u;
        }
        (void)memcpy(dest, src, copy_len);
        dest[copy_len] = '\0';
        status = (copy_len < src_len) ? COPY_STATUS_TRUNCATED : COPY_STATUS_OK;
    }

    return status;
}
