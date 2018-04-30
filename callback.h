/*
 * File:   callback.c
 * Author: DoI
 */

void callback_pre_send(int sock, void * testcase, unsigned long len);
void callback_post_send(int sock);
void callback_ssl_pre_send(SSL * ssl, void * testcase, unsigned long len);
void callback_ssl_post_send(SSL * ssl);