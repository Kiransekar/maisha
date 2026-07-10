#ifndef STUB_SETJMP_H
#define STUB_SETJMP_H
typedef int jmp_buf[16];
int setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val);
#endif
