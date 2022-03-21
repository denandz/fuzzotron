/*
 * File:   fuzzotron.c
 * Author: DoI
 *
 * Fuzzotron is a simple network socket fuzzer. Connect to a tcp or udp port
 * and fire some testcases generated with either blab or radamsa.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <linux/limits.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "monitor.h"
#include "fuzzotron.h"
#include "sender.h"
#include "generator.h"
#include "trace.h"
#include "util.h"

// Struct to hold arguments passed to the monitor thread
struct monitor_args mon_args;

volatile int stop = 0;   // the global 'stop fuzzing' variable. When set to 1, all threads will spool
                         // their cases to disk and exit.
int timeout_stop = 0; // similar to stop, but needed to know if the test cases should be saved.
pthread_mutex_t runlock;
int check_pid = 0; // server pid to check for crash.
int timeout_secs = 0; // time in seconds until fuzzing stops.
struct fuzzer_args fuzz; // Arguments for the fuzzer threads
char * output_dir = NULL; // directory for potential crashes

static unsigned long cases_sent = 0;
static unsigned long cases_jettisoned = 0;
static unsigned long paths = 0;

int main(int argc, char** argv) {

    memset(&fuzz, 0x00, sizeof(fuzz));
    // parse arguments
    int c, threads = 1;
    static int use_blab = 0, use_radamsa = 0;
    char * logfile = NULL, * regex = NULL;
    fuzz.protocol = 0; fuzz.is_tls = 0; fuzz.destroy = 0;

    static struct option arg_options[] = {
        {"alpn", required_argument, 0, 'l'},
        {"blab", no_argument, &use_blab, 1},
        {"radamsa", no_argument, &use_radamsa, 1},
        {"ssl", no_argument, &fuzz.is_tls, 1},
        {"grammar",  required_argument, 0, 'g'},
        {"output",  required_argument, 0, 'o'},
        {"directory",  required_argument, 0, 'd'},
        {"protocol",  required_argument, 0, 'p'},
        {"destroy", no_argument, &fuzz.destroy, 1},
        {"checkscript", required_argument, 0, 'z'},
        {"trace", required_argument, 0, 's'},
        {0, 0, 0, 0}
    };
    int arg_index;
    while((c = getopt_long(argc, argv, "d:c:h:p:g:t:m:c:P:r:w:s:z:o:k:", arg_options, &arg_index)) != -1){
        switch(c){
            case 'c':
                // Define PID to check for crash
                check_pid = atoi(optarg);
                printf("[+] Monitoring PID %d\n", check_pid);
                break;

            case 'd':
                // define test case directory for blab
                fuzz.in_dir = optarg;
                if(directory_exists(fuzz.in_dir) < 0){
                    fatal("Could not open %s\n", fuzz.in_dir);
                }
                break;

            case 'g':
                // define grammar
                fuzz.grammar = optarg;
                break;

            case 'h':
                // define host
                fuzz.host = optarg;
                break;

            case 'k':
                // set time for fuzzing to run (in seconds)
                timeout_secs = atoi(optarg);
                break;

            case 'l':
                // set ALPN string
                fuzz.alpn = optarg;
                break;

            case 'm':
                // Log file to monitor
                logfile = optarg;
                break;

            case 'o':
                // Output dir for crashes
                output_dir = optarg;

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

            case 'r':
                // define regex for monitoring
                regex = optarg;
                break;

            case 't':
                // define threads
                threads = atoi(optarg);
                break;

            case 's':
                fuzz.shm_id = atoi(optarg);
                break;

            case 'z':
                fuzz.check_script = optarg;
                break;

           }
    }

    // check argument sanity
    if((fuzz.host == NULL) || (fuzz.port == 0 && fuzz.protocol != 3) ||
            (use_blab == 1 && use_radamsa == 1) ||
            (use_blab == 0 && use_radamsa == 0) ||
            (use_blab == 1 && fuzz.in_dir && !fuzz.shm_id) ||
            (use_radamsa == 1 && fuzz.grammar != NULL) ||
            (fuzz.protocol == 0) || (output_dir == NULL)){
        help();
        return -1;
    }

    // if we're using blab, ensure we have a grammar defined
    if(use_blab == 1 && fuzz.grammar == NULL){
        fatal("If using blab, -g or --grammar must be specified\n");
    }
    // if we're using radamsa, ensure the directory with the example cases is defined
    if(use_radamsa == 1 && fuzz.in_dir == NULL){
        fatal("If using radamsa, -d or --directory must be specified\n");
    }

    if(fuzz.shm_id && threads > 1){
        fatal("Tracing only supported single threaded");
    }
    if(fuzz.shm_id && fuzz.gen == BLAB && fuzz.in_dir == NULL){
        fatal("Blab and tracing requires --directory");
    }
    if(fuzz.shm_id && use_blab == 1 && fuzz.in_dir){
        // Note: hmmm, maybe using blab and instrumentation is a good idea... Save testcases that blab generates
        // that hit new paths and use this to seed a mutation-based fuzzer?
        puts(GRN "[+] Experimental discovery mode enabled\n" RESET);
    }

    if(fuzz.is_tls){
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
    }
    
    if(logfile != NULL){
        if(regex == NULL){
            printf("[!] No regex specified, falling back to Crash-Detect mode\n");
        }
        else {
            printf("[+] Monitoring logfile %s\n", logfile);
            // Spawn the monitor
            int rc;
            pthread_t monitor;

            mon_args.file = logfile;
            mon_args.regex = regex;

            printf("[+] Spawning monitor\n");
            rc = pthread_create(&monitor, NULL, call_monitor, NULL);
            if(rc){
                fatal("Creating pthread failed: %s\n", strerror(errno));
            }
            printf("[+] Monitor Spawned!\n");
        }
    }

    if(fuzz.check_script){
        if(!file_exists(fuzz.check_script)){
            printf("[!] File %s not found\n", fuzz.check_script);
            help();
            return -1;
        }

        printf("[+] Using check script: %s\n", fuzz.check_script);
    }

    fuzz.tmp_dir = CASE_DIR;
    if(directory_exists(fuzz.tmp_dir) < 0){
        if(mkdir(fuzz.tmp_dir, 0755)<0){
            fatal("[!] Could not mkdir %s: %s\n", fuzz.tmp_dir, strerror(errno));
        }
    }

    if(directory_exists(output_dir) < 0){
        if(mkdir(output_dir, 0755)<0){
            fatal("[!] Could not mkdir %s: %s\n", output_dir, strerror(errno));
        }
    }

    if(use_blab == 1){
        fuzz.gen = BLAB;
    }
    else if(use_radamsa){
        fuzz.gen = RADAMSA;
    }

    if (pthread_mutex_init(&runlock, NULL) != 0){
        fatal("[!] pthread_mutex_init failed");
    }

    signal(SIGPIPE, SIG_IGN);
    pthread_t workers[threads];
    int i;
    struct worker_args targs[threads];
    for(i = 1; i <= threads; i++){

        targs[i-1].thread_id = i;
        targs[i-1].threads = threads;

        printf("[+] Spawning worker thread %d\n", i);
        if(pthread_create(&workers[i-1], NULL, worker, &targs[i-1]) > 0)
            fatal("Creating pthread failed: %s\n", strerror(errno));

        usleep(2000);
    }

    pthread_t timeout_monitor;
    if(timeout_secs){
        printf("[+] Spawning timeout monitor\n");
        if(pthread_create(&timeout_monitor, NULL, timer_job, NULL) > 0)
            fatal("Creating pthread failed: %s\n", strerror(errno));
        printf("[.] Timeout monitor alive and will stop testing in %d seconds\n", timeout_secs);
    }


    char spinner[4] = "|/-\\";
    struct spint { unsigned i:2; } s;
    s.i=0;
    while(1){
        usleep(50000);
        if(stop == 1){
            printf("\n");
            break;
        }

        printf("[%c] Sent cases: %lu", spinner[s.i],  cases_sent);
        if(fuzz.shm_id)
            printf(" Paths:%lu Jettisoned: %lu\r", paths, cases_jettisoned);
        else
            printf("\r");

        fflush(stdout);
        s.i++;
    }

    if(timeout_secs){
        pthread_join(timeout_monitor, NULL);
    }
    for(i = 1; i <= threads; i++){
        pthread_join(workers[i-1], NULL);
    }

    pthread_mutex_destroy(&runlock);
    printf("[.] Done. Total testcases issued: %lu\n", cases_sent);

    return 1;
}

void * call_monitor(){
    monitor(mon_args.file, mon_args.regex);
    return NULL;
}

// timeout monitor's flow - checks if the elapsed time has passed the defined timeout, and if so triggers a stop
void * timer_job(void * args __attribute__((unused))){
    time_t start_time;

    time(&start_time);
    while(stop == 0 && difftime(time(NULL), start_time) < timeout_secs){
        sleep(1);
    }

    if(stop == 0){
        pthread_mutex_lock(&runlock);
        printf("[!] Reached timeout\n");
        stop = 1;
        timeout_stop = 1;
        pthread_mutex_unlock(&runlock);
    }
    return NULL;
}

// worker thread, generate cases and sends them
void * worker(void * worker_args){
    struct worker_args *thread_info = (struct worker_args *)worker_args;
    printf("[.] Worker %u alive\n", thread_info->thread_id);

    int deterministic = 1;

    // Use the PID as the prefix for generation
    char prefix[25];
    sprintf(prefix,"%d",(int)syscall(SYS_gettid));

    // Testcases
    testcase_t * cases = 0x00;
    testcase_t * entry = 0x00;

    uint32_t exec_hash;
    int r;

    if(fuzz.shm_id > 0){
        printf("[.] Trace enabled\n");
        memset(fuzz.virgin_bits, 255, MAP_SIZE);
        fuzz.trace_bits = setup_shm(fuzz.shm_id);
    }

    if(fuzz.shm_id > 0 && fuzz.gen == RADAMSA){
        cases = load_testcases(fuzz.in_dir, ""); // load all cases from the provided dir
        entry = cases;

        if(fuzz.trace_bits == 0){
            return NULL;
        }

        // A server crash in calibration is not handled gracefully, this needs to be tidied up
        while(entry){
            memset(fuzz.trace_bits, 0x00, MAP_SIZE);
            if(fuzz.send(fuzz.host, fuzz.port, entry) < 0){
                fatal("[!] Failure in calibration\n");
            }

            exec_hash = wait_for_bitmap(fuzz.trace_bits);
            if(exec_hash > 0){
                if(has_new_bits(fuzz.virgin_bits, fuzz.trace_bits) > 1){
                    r = calibrate_case(entry, fuzz.trace_bits);
                    if(r == 0)
                        cases_jettisoned++;
                    else{
                        paths++;
                    }
                }
            }
            entry = entry->next;
            cases_sent++;
        }
        printf("\n[.] Loaded Paths: %lu Jettisoned: %lu\n", paths, cases_jettisoned);
        free_testcases(cases);
    }

    while(1){
        // generate the test cases
        if(fuzz.gen == BLAB){
            cases = generator_blab(CASE_COUNT, fuzz.grammar, fuzz.tmp_dir, prefix);
        }

        else if(fuzz.gen == RADAMSA){
            // Perform some deterministic mutations before going off to radamsa.
            // currently limited to the first thread.
            if(deterministic == 1 && thread_info->thread_id == 1){
                //printf("Performing deterministic mutations\n");

                testcase_t * orig_cases = load_testcases(fuzz.in_dir, ""); // load all cases from the provided dir
                testcase_t * orig_entry = orig_cases;

                while(orig_entry){
                    if(determ_fuzz(orig_entry->data, orig_entry->len, thread_info->thread_id) < 0){
                        free_testcases(orig_cases);
                        goto cleanup;
                    }
                    orig_entry = orig_entry->next;

                    if(stop < 0){
                        break;
                    }
                }
                free_testcases(orig_cases);

                if(deterministic > 0){
                    deterministic = 0;
                    if(fuzz.shm_id)
                        printf("[.] Deterministic mutations completed, sent: %lu paths: %lu\n", cases_sent, paths);
                    else
                        printf("[.] Deterministic mutations completed, sent: %lu\n", cases_sent);
                }

                if(stop < 0) // an error or crash occured during the deteministic steps
                    break;

                continue;
            }

            cases = generator_radamsa(CASE_COUNT, fuzz.in_dir, fuzz.tmp_dir, prefix);
        }

        if(send_cases(cases) < 0){
            goto cleanup;
        }
    }

cleanup:
    printf("[!] Thread %d exiting\n", thread_info->thread_id);
    return NULL;
}

// Perform determisistic mutations, id and max paramters for splitting work load across threads
int determ_fuzz(char * data, unsigned long len, unsigned int id){
    unsigned long max = len << 3;
    unsigned long offset = 0;
    unsigned long determ_batch_size = strtol(CASE_COUNT, NULL, 10);

    if(determ_batch_size == 0){
        fatal("[!] determ_batch_size strtol returned 0\n");
    }

    testcase_t * cases;

    if(max < determ_batch_size){
        cases = generate_swbitflip(data, len, offset, max);
        if(send_cases(cases)<0){
            return -1;
        }
    }
    else{
        unsigned long i = 0;

        while(i < (max/determ_batch_size)){
            cases = generate_swbitflip(data, len, offset, determ_batch_size);
            if(send_cases(cases) < 0){
                return -1;
            }
            offset = offset+determ_batch_size;
            i++;
        }
        if(max % determ_batch_size > 0){
            //printf("%d generating remainder len %lu start %lu count %lu\n", id, len, offset, max % 100);
            cases = generate_swbitflip(data, len, offset, max % determ_batch_size);
            if(send_cases(cases) < 0){
                return -1;
            }
        }
    }

    return 0;
}

// Send all cases in a struct. return -1 if any failure, otherwise 0. Frees the supplied cases struct
// and updates global counters.
int send_cases(void * cases){
    int ret = 0, r = 0;
    testcase_t * entry = cases;
    uint32_t exec_hash;

    while(entry){
        if(entry->len == 0){
            // no data in test case, go to next one. Radamsa will generate null
            // testcases sometimes...
            entry = entry->next;
            continue;
        }
        if(fuzz.shm_id){
            memset(fuzz.trace_bits, 0x00, MAP_SIZE);
            ret = fuzz.send(fuzz.host, fuzz.port, entry);
            if(ret < 0)
                break;

            exec_hash = wait_for_bitmap(fuzz.trace_bits);
            if(exec_hash > 0){
                if(has_new_bits(fuzz.virgin_bits, fuzz.trace_bits) > 1){
                    r = calibrate_case(entry, fuzz.trace_bits);
                    if(r == -1){
                        // crash during calibration?
                        ret = r;
                        break;
                    }
                    else if(r == 0){
                        cases_jettisoned++;
                    }
                    else{
                        paths++; // new case! save and perform some deterministic fuzzing
                        save_case(entry->data, entry->len, exec_hash, fuzz.in_dir);

                        if(fuzz.gen != BLAB){
                            determ_fuzz(entry->data, entry->len, 1); // attention defecit fuzzing
                        }
                    }
                }
            }
        }
        else {
            // no instrumentation
            ret = fuzz.send(fuzz.host, fuzz.port, entry);

            if(ret < 0)
                break;
        }

        entry = entry->next;
        cases_sent++;
    }

    if(check_stop(cases, ret)<0){
        free_testcases(cases);
        return -1;
    }

    free_testcases(cases);
    return 0;
}

// checks the return code from send_cases et-al and sets the global stop variable if
// its time to stop fuzzing and saves the cases.
int check_stop(void * cases, int result){
    int ret = result;

    // if global stop, save cases
    pthread_mutex_lock(&runlock);
    if(stop == 1){
        // save cases
        if(!timeout_stop){
            save_testcases(cases, output_dir);
        }
        pthread_mutex_unlock(&runlock);
        return -1;
    }
    pthread_mutex_unlock(&runlock);

    // If process id is supplied, check it exists and set stop if it doesn't
    if(check_pid > 0){
        if((pid_exists(check_pid)) == -1){
            ret = -1;
        }
        else{
            ret = 0;
        }
    }

    if(fuzz.check_script){
        int r;
        r = run_check(fuzz.check_script);
        if( r != 1){
            printf("[!] Check script %s returned %d, stopping\n", fuzz.check_script, r);
            ret = -1;
        }
        else{
            ret = 0;
        }
    }

    if(ret == -1){
        // We have experienced a crash. set the global stop var
        pthread_mutex_lock(&runlock);
        stop = 1;
        save_testcases(cases, output_dir);
        pthread_mutex_unlock(&runlock);
    }

    return ret;
}

/* Calibrate a new testcase. Returns 1 if the testcase behaves deterministically, 0 if it does not
 * EG: has variable behaviour. Without this, non deterministic features would cause a bunch of
 * tiny, useless test cases. Return -1 on failure. Timeout on waiting for the bitmap to stop changing
 * is an immediate 0.
 */
int calibrate_case(testcase_t * testcase, uint8_t * trace_bits){
    uint32_t hash, tmp_hash, i;

    memset(trace_bits, 0x00, MAP_SIZE);
    if(fuzz.send(fuzz.host, fuzz.port, testcase) < 0){
        return -1;
    }

    hash = wait_for_bitmap(trace_bits); // check null
    if(hash == 0 || hash == NULL_HASH) // unstable test case, bitmap still changing after 2 seconds, or no bitmap change
        return 0;

    for(i = 0; i < 4; i++){
        memset(trace_bits, 0x00, MAP_SIZE);
        if(fuzz.send(fuzz.host, fuzz.port, testcase) < 0){
            return -1;
        }
        tmp_hash = wait_for_bitmap(trace_bits);
        if(tmp_hash != hash){
            // printf("[!] Non deterministic testcase detected\n");
            return 0;
        }
    }

    // timing and case trimming should eventually go here

    return 1;
}

int pid_exists(int pid){
    struct stat s;
    char path[PATH_MAX];

    sprintf(path, "/proc/%d", pid);
    if(stat(path, &s) == -1){
        // PID not found
        printf("[!!] PID %d not found. Check for server crash\n", pid);
        return -1;
    }

    // PID found
    return 0;
}

int run_check(char * script){

    if(access(script, X_OK) < 0){
        fatal("[!] Error accessing check script %s: %s\n", script, strerror(errno));
    }

    int out_pipe[2];
    int err_pipe[2];
    pid_t pid;
    char ret[2];
    memset(ret, 0x00, 2);

    if(pipe(out_pipe) < 0 || pipe(err_pipe) < 0){
        fatal("[!] Error with pipe: %s\n", strerror(errno));
    }
    if((pid = fork()) == 0){
            dup2(err_pipe[1], 2);
            dup2(out_pipe[1], 1);
            close(out_pipe[0]);
            close(out_pipe[1]);
            close(err_pipe[0]);
            close(err_pipe[1]);

            char *args[] = {script, 0};
            execv(args[0], args);

            exit(0);
    }

    else if(pid < 0){
            fatal("[!] FORK FAILED!\n");
    }
    else{
        close(err_pipe[1]);
        close(out_pipe[1]);
        waitpid(pid, NULL, 0);
        if(read(out_pipe[0], ret, 1) < 0){
            fatal("read() failed");
        };
        close(err_pipe[0]);
        close(out_pipe[0]);
        return atoi(&ret[0]);
    }

    return -1;
}

int file_exists(char * file){
    struct stat s;
    return(stat(file, &s) == 0);
}

/*
*  Check if a directory exists, returns 0 on success or < 0 on failure.
*/
int directory_exists(char * dir){
    DIR * d = opendir(dir);
    if(d != NULL){
        closedir(d);
        return 0;
    }
    else{
        return -1;
    }
}

void help(){
    // Print the help and exit
    printf("FuzzoTron - A Fuzzing Harness built around OUSPG's Blab and Radamsa.\n\n");
    printf("Usage (crash-detect mode - blab): ./fuzzotron --blab -g http_request -h 127.0.0.1 -p 80 -P tcp -o output\n");
    printf("Usage (crash-detect mode - radamsa): ./fuzzotron --radamsa --directory testcases/ -h 127.0.0.1 -p 80 -P tcp -o output\n");
    printf("Usage (log-monitor mode): ./fuzzotron --blab -g http_request -h 127.0.0.1 -p 80 -P tcp -m /var/log/messages -r 'segfault' -o output\n");
    printf("Usage (process-monitor mode): ./fuzzotron --radamsa --directory testcases/ -h 127.0.0.1 -p 80 -P tcp -c 23123 -o output\n\n");
    printf("General Options:\n");
    printf("\t-k\t\tNumber of seconds before fuzzing stops\n");
    printf("\t-o\t\tOutput directory for crashes REQUIRED\n");
    printf("\t-t\t\tNumber of worker threads\n");
    printf("\t--trace\t\tUse AFL style tracing. Single threaded only, see README.md\n\n");
    printf("Generation Options:\n");
    printf("\t--blab\t\tUse Blab for testcase generation\n");
    printf("\t-g\t\tBlab grammar to use\n");
    printf("\t--radamsa\tUse Radamsa for testcase generation\n");
    printf("\t--directory\tDirectory with original test cases\n\n");
    printf("Connection Options:\n");
    printf("\t-h\t\tIP of host to connect to REQUIRED\n");
    printf("\t-p\t\tPort to connect to REQUIRED\n");
    printf("\t-P\t\tProtocol to use (tcp,udp) REQUIRED\n");
    printf("\t--ssl\t\tUse SSL for the connection\n");
    printf("\t--destroy\tUse TCP_REPAIR mode to immediately destroy the connection, do not send FIN/RST.\n\n");
    printf("Monitoring Options:\n");
    printf("\t-c\t\tPID to check - Fuzzotron will halt if this PID dissapears\n");
    printf("\t-m\t\tLogfile to monitor\n");
    printf("\t-r\t\tRegex to use with above logfile\n");
    printf("\t-z\t\tCheck script to execute. Should return 1 on server being okay and anything else otherwise.\n");
    exit(0);
}
