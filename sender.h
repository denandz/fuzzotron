/*
 * File:   sender.h
 * Author: DoI
 *
 */

#ifndef SENDER_H
#define SENDER_H

#include "generator.h"

void setup_tcp(int sock);
int send_udp(char * host, int port, testcase_t * testcase);
int send_tcp(char * host, int port, testcase_t * testcase);
void destroy_socket(int sock);
unsigned char * next_protos_parse(size_t * outlen, const char * in);
int send_unix(char * path, int port /* not used for UNIX sockets */, testcase_t * testcase);

#endif