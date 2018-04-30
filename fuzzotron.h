/*
 * File:   fuzzotron.h
 * Author: DoI
 */

#include <stdint.h>
#include "trace.h"

// Tunables
#define CASE_COUNT "100"
#define CASE_DIR "/dev/shm/fuzzotron"

#define RADAMSA 0x01
#define BLAB 0x02

extern int stop; // set to 1 to stop fuzzing

struct fuzzer_args {
    int gen; // generator for the test cases. Blab, radamsa, custom etcetera.
    char * in_dir;
    char * grammar;
    char * tmp_dir; // temporary directory to store test cases
    char * host;
    char * check_script; // script to check server status. Must return 1 on server-up or anything else on server-down (crashed)
    int protocol; // 1 == TCP, 2 == UDP
    int destroy; // Use TCP_REPAIR to destroy the connection, do not send a RST after the testcase
    int port;
    int is_tls;
    char * alpn;

    int32_t shm_id; // Shared memory address for AFL style tracing
    uint8_t * trace_bits;
    uint8_t virgin_bits[MAP_SIZE];

    int (*send)(char * host, int port, char * data, unsigned long len); // pointer to method to send a packet.
};

extern struct fuzzer_args fuzz;

struct monitor_args {
    char * file;
    char * regex;
};

// Worker args struct containing some thread information. Used for divvying up deterministic mutations amongst multiple threads.
struct worker_args {
    unsigned int thread_id; // specific thread identifier
    unsigned int threads; // total number of threads
};

int main(int argc, char** argv);
void * call_monitor();
void * worker();
int pid_exists(int pid);
int storeTestCases(char * prefix, char * crashId);
int spawnProcess();
void help();
int run_check(char * script);
int directory_exists(char * dir);
int file_exists(char * file);
int calibrate_case(char * testcase, unsigned long len, uint8_t * trace_bits);
int determ_fuzz(char * data, unsigned long len, unsigned int id);
int send_cases(void * cases);
int check_stop(void * cases, int result);