/*
 * File:   callback.c
 * Author: DoI
 *
 * This file defines a set of callback methods that can be used
 * to perform custom actions prior to, or after, sending a test
 * case. Relies on on -O3 compiler optimization to prune out the 
 * calls if there is nothing defined in these methods.
 */

// Called after the socket is connected but before the test case is sent.
void callback_pre_send(int sock, void * testcase, unsigned long len){
    /*
    your custom connection setup code goes here!
    tip: xxd -i can be used to spit out C arrays

    char packet[] = {0x40, 0x52};

    write(sock, packet, sizeof(packet));
    */
}

// Called after the testcase is sent but before the socket is closed.
void callback_post_send(int sock){

}