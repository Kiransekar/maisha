/* fw_types.h — minimal local stand-in for <stdint.h>/<stddef.h>/<string.h>,
 * scoped to exactly what this firmware module uses (so cppcheck's
 * unused-type/macro checks don't fire on declarations nothing references,
 * and so the fix-loop simulation doesn't need external -I stub headers).
 */
#ifndef FW_TYPES_H
#define FW_TYPES_H

typedef signed int   int32_t;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

char *strcpy(char *dest, const char *src);

#endif
