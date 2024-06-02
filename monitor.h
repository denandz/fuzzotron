/*
 * File:   monitor.h
 * Author: DoI
 *
 */

#ifndef MONITOR_H
#define MONITOR_H

#include <pcre.h>

int monitor(char * file, char * regex);
int parse_line(char* line, pcre *regex);
pcre * compile_regex(char* regex);

#endif
