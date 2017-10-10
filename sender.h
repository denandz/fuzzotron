/*
 * File:   sender.h
 * Author: DoI
 *
 */

void setup_tcp(int sock);
int send_udp(char * host, int port, char * packet, unsigned long packet_len, int ssl);
int send_tcp(char * host, int port, char * packet, unsigned long packet_len, int ssl);
void destroy_socket(int sock);
