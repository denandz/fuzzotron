/*
 * File:   monitor.h
 * Author: DoI
 *
 */

#include <pcre.h>

int monitor(char * file, char * regex);
int parse_line(char* line, pcre *regex);
struct real_pcre * compile_regex(char* regex);
