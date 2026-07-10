#ifndef STUB_SIGNAL_H
#define STUB_SIGNAL_H
typedef int sig_atomic_t;
typedef void (*__sighandler_t)(int);
__sighandler_t signal(int signum, __sighandler_t handler);
int raise(int sig);
#endif
