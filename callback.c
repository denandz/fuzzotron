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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "generator.h"
#include "util.h"

// Called after the socket is connected but before the test case is sent.
void callback_pre_send(int sock, testcase_t * testcase){
    /*
    your custom connection setup code goes here!
    tip: xxd -i can be used to spit out C arrays

    char packet[] = {0x40, 0x52};
    write(sock, packet, sizeof(packet));

    or modify the testcase about to be sent somehow

    memset(testcase->data, 0x00, 1); // set first byte to null

    or change something about the socket, such as enabling broadcasting or setting a source port

    int broadcast = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
    {
        fatal("[!] Error: Could not set broadcast: %s\n", strerror(errno));
    }

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(68);

    if (bind(sock, (struct sockaddr *) &client_addr, sizeof(client_addr)) < 0) {
        fatal("[!] Error: Could not bind socket: %s\n", strerror(errno));
    }

    */
}

// Called after the testcase is sent but before the socket is closed.
void callback_post_send(int sock){

}

void callback_ssl_pre_send(SSL * ssl, testcase_t * testcase){

}

void callback_ssl_post_send(SSL * ssl){

}