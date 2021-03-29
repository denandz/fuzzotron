/*
 * File:   callback.c
 * Author: DoI
 *
 * This file defines a set of callback methods that can be used
 * to perform custom actions prior to, or after, sending a test
 * case. Relies on an -O3 compiler optimization to prune out the
 * calls if there is nothing defined in these methods.
 */

#include <openssl/ssl.h>

#include "generator.h"

// Called after the socket is connected but before the test case is sent.
void callback_pre_send(int sock, testcase_t * testcase){
    /*
    your custom connection setup code goes here!
    tip: xxd -i can be used to spit out C arrays

    char packet[] = {0x40, 0x52};

    write(sock, packet, sizeof(packet));

    or modify the testcase about to be sent somehow
    memset(testcase->data, 0x00, 1); // set first byte to null
    */
}

// Called after the testcase is sent but before the socket is closed.
void callback_post_send(int sock){

}

void callback_ssl_pre_send(SSL * ssl, testcase_t * testcase){

}

void callback_ssl_post_send(SSL * ssl){

}