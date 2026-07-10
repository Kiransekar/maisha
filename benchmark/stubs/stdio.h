#ifndef STUB_STDIO_H
#define STUB_STDIO_H
#include <stddef.h>
typedef struct maisha_stub_file_tag FILE;
int printf(const char *fmt, ...);
int fprintf(FILE *stream, const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);
int snprintf(char *buf, size_t n, const char *fmt, ...);
int scanf(const char *fmt, ...);
int fscanf(FILE *stream, const char *fmt, ...);
int puts(const char *s);
#endif
