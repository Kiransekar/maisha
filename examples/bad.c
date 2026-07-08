/* examples/bad.c — deliberately non-compliant fixture for Sentinel-C demos.
 * Violates MISRA C:2012, BARR-C:2018 and CERT C rules on purpose.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int global_counter;   /* basic type instead of stdint (MISRA Dir 4.6 / BARR 5.2) */

// int old_debug_flag = 1;  /* commented-out code (MISRA Dir 4.4 / BARR 2.2) */

unsigned long factorial(unsigned long n)
{
    if (n <= 1)
        return 1ul;                    /* lowercase 'l' suffix; if without braces */
    return n * factorial(n - 1u);      /* recursion (MISRA 17.2 / BARR 6.1a) */
}

int parse_and_log(const char *input)
{
    char buf[16];
    int mode = 010;                    /* octal constant (MISRA 7.1) */
    char *dyn = malloc(32);            /* dynamic allocation (MISRA 21.3) */

    strcpy(buf, input);                /* unbounded copy (CERT STR31-C) */
    sprintf(buf, "%s!", input);        /* unbounded format (CERT STR31-C) */
    printf("mode=%d buf=%s\n", mode, buf);  /* stdio in production (MISRA 21.6) */

    int value = atoi(input);           /* no error detection (CERT ERR34-C / MISRA 21.7) */
    if (value = mode)                  /* assignment in condition (MISRA 13.4) */
        goto done;                     /* goto (MISRA 15.1) */

    switch (value) {                   /* no default (MISRA 16.4 / BARR 8.5) */
    case 1:
        global_counter++;
        break;
    case 2:
        global_counter--;
        break;
    }

done:
    free(dyn);
    system("sync");                    /* command processor (CERT ENV33-C / MISRA 21.8) */
    return value;
}

double ratio(double a, double b)
{
	double r = a / b;                  /* tab indent (BARR 3.2a); no zero check (CERT INT33-C class) */
    if (r == 0.5)                      /* float equality (CERT FLP37-C) */
        r = 0.0;
    return r;
}
