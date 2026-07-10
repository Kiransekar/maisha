#ifndef STUB_STDDEF_H
#define STUB_STDDEF_H
/* Use the compiler's own built-in width macros rather than hardcoding
   "unsigned long" — that's correct on LP64 hosts but wrong on Windows/LLP64,
   where size_t is "unsigned long long". Keeps this stub portable across the
   hosts Maisha's clang-tidy adapter might run on. */
#ifdef __SIZE_TYPE__
typedef __SIZE_TYPE__ size_t;
#else
typedef unsigned long size_t;
#endif
#ifdef __PTRDIFF_TYPE__
typedef __PTRDIFF_TYPE__ ptrdiff_t;
#else
typedef long ptrdiff_t;
#endif
#ifndef NULL
#define NULL ((void*)0)
#endif
#endif
