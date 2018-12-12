#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include "util.h"
#include "sender.h"
#include "fuzzotron.h"

struct fuzzer_args fuzz;

void help(){
    // Print the help and exit
    printf("Replay - Send a testcase, the same way Fuzzotron does\n\n");
    printf("Usage: ./replay -h 127.0.0.1 -p 80 -P tcp -c 23123 some_file\n\n");
    printf("\t-h\t\tIP of host to connect to\n");
    printf("\t-p\t\tPort to connect to\n");
    printf("\t-P\t\tProtocol to use (tcp,udp)\n");
    printf("\t--ssl\t\tUse SSL for the connection\n");
    printf("\t--destroy\tUse TCP_REPAIR mode to immediately destroy the connection, do not send FIN/RST.\n");
    exit(0);
}

int main(int argc, char ** argv){
    int c;
    FILE * fp;
    char * data; 
    unsigned long data_len = 0;
    
    memset(&fuzz, 0x00, sizeof(fuzz));

    static struct option arg_options[] = {
        {"alpn", required_argument, 0, 'l'},
        {"ssl", no_argument, &fuzz.is_tls, 1},
        {"protocol",  required_argument, 0, 'p'},
        {"destroy", no_argument, &fuzz.destroy, 1},
        {0, 0, 0, 0}
    };

    int arg_index;
    while((c = getopt_long(argc, argv, "h:p:g:t:m:c:P:r:w:s:z:o:", arg_options, &arg_index)) != -1){
        switch(c){
            case 'h':
                // define host
                fuzz.host = optarg;
                break;

            case 'l':
                // set ALPN string
                fuzz.alpn = optarg;
                break;

            case 'p':
                // define port
                fuzz.port = atoi(optarg);
                break;

            case 'P':
                // define protocol
                if((strcmp(optarg,"udp") != 0) && (strcmp(optarg,"tcp") != 0) && (strcmp(optarg,"unix") != 0)){
                        fatal("Please specify either 'tcp', 'udp' or 'unix' for -P\n");
                }
                if(strcmp(optarg,"tcp") == 0){
                            fuzz.protocol = 1;
                            fuzz.send = send_tcp;
                }
                else if(strcmp(optarg,"udp") == 0){
                            fuzz.protocol = 2;
                            fuzz.send = send_udp;
                }
                else if(strcmp(optarg,"unix") == 0){
                    fuzz.protocol = 3;
                    fuzz.send = send_unix;
                }

                break;
           }
    }

    if((fuzz.host == NULL) || (fuzz.port == 0 && fuzz.protocol != 3) ||
            (fuzz.protocol == 0)){
        help();
        return 0;
    }

    char * file = argv[optind];
    if((fp = fopen(file, "r"))== NULL){
            fatal("[!] Error: Could not open file %s\n", strerror(errno));
    }

    if (fseek(fp, 0L, SEEK_END) == 0) {
        long bufsize = ftell(fp);
        if (bufsize == -1){
            fatal("[!] Error with ftell: %s", strerror(errno));
        }
        else if(bufsize == 0){ // handle empty file
            fatal("Zero length file");
        }

        // Go back to the start of the file.
        if (fseek(fp, 0L, SEEK_SET) != 0){
            fatal("[!] Error: could not fseek: %s\n", strerror(errno));
        }

        // Read the entire file into memory.
        data_len = bufsize;
        ft_malloc(data_len, data);
        if(fread(data, sizeof(char), data_len, fp) != data_len){
            fatal("[!] Error: fread");
        }
        
        if (ferror( fp ) != 0){
            fatal("[!] Error: fread: %s\n", strerror(errno));
        }
    }
    fclose(fp);
    
    if(data_len > 0){
        printf("Sending: %s bytes: %lu\n", file, data_len);
        fuzz.send(fuzz.host, fuzz.port, data, data_len);
        free(data);
    }

    return 1;
}
