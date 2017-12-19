/*
 * File:   util.h
 * Author: DoI
 */

#include <stdio.h>
#include <stdlib.h>

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

#define fatal(x...) \
    do { \
        fprintf(stderr, RED "[!] ERROR: " RESET); \
        fprintf(stderr, x); \
        fprintf(stderr, "\n         Location : %s(), %s:%d\n\n", \
        __FUNCTION__, __FILE__, __LINE__); \
        exit(0);\
    } while(0)

#define ft_malloc(len,ptr) \
    do { \
        if(NULL == (ptr = malloc(len))){\
            fatal("[!] Malloc failed\n"); \
        }\
    } while(0)
