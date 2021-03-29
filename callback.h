/*
 * File:   callback.c
 * Author: DoI
 */

#ifndef CALLBACK_H
#define CALLBACK_H

#include "generator.h"

void callback_pre_send(int sock, testcase_t *testcase);
void callback_post_send(int sock);
void callback_ssl_pre_send(SSL * ssl, testcase_t * testcase);
void callback_ssl_post_send(SSL * ssl);

#endif