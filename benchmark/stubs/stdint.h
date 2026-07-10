#ifndef STUB_STDINT_H
#define STUB_STDINT_H
typedef signed char        int8_t;
typedef unsigned char      uint8_t;
typedef signed short       int16_t;
typedef unsigned short     uint16_t;
typedef signed int         int32_t;
typedef unsigned int       uint32_t;
typedef signed long long   int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long      uintptr_t;
typedef signed long        intptr_t;
#define UINT32_MAX 0xFFFFFFFFu
#define INT32_MAX  0x7FFFFFFF
#define INT32_MIN  (-INT32_MAX - 1)
#define UINT8_MAX  0xFFu
#define UINT16_MAX 0xFFFFu
#endif
