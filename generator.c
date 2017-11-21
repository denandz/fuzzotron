/*
 * File:   generator.c
 * Author: DoI
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>

#include "generator.h"
#include "util.h"

// Executes radamsa and returns a linked list of test cases
// this is pretty inefficient, and running a radamsa server and reading from the socket
// would likely be a far, far smarter idea.
struct testcase * generator_radamsa(char * count, char * testcase_dir, char * path, char * prefix){
    pid_t pid;
    int s;
    char output[PATH_MAX];
    struct testcase * testcase;

    snprintf(output, PATH_MAX, "%s/%s-%%n", path, prefix);
    char * argv[] = { "radamsa", "-n", count, "-r", "-o", output, testcase_dir, 0 };

    if((pid = fork()) == 0){
        execvp(argv[0], argv);
        exit(0);
    }
    else if(pid < 0){
        fatal("[!] generator_radamsa fork() failed: %s", strerror(errno));
    }
    else
        waitpid(pid, &s, 0x00);
    
    testcase = load_testcases(path, prefix);
    return testcase;
}

// Executes blab and returns a linked list of test cases
struct testcase * generator_blab(char * count, char * grammar, char * path, char * prefix){
    pid_t pid;
    int s;
    char output[PATH_MAX];
    struct testcase * testcase;

    snprintf(output, PATH_MAX, "%s/%s-%%n", path, prefix);      

    char * argv[] = { "blab", grammar, "-n", count , "-o", output, 0 };

    if((pid = fork()) == 0){
        execvp(argv[0], argv);
        exit(0);
    }
    else if(pid < 0){
        printf("[!] generator_blab fork() failed: %s", strerror(errno));
        return 0;
    }
    else
        waitpid(pid, &s, 0x00);
    
    testcase = load_testcases(path, prefix);

    return testcase;
}

// single walking bit, returns a linked struct of testcases
struct testcase * generate_swbitflip(char * data, unsigned long in_len, unsigned long offset, unsigned long count){
    unsigned long i = 0;
    char * output, * input;
    struct testcase * testcase, * entry;
    ft_malloc(sizeof(struct testcase),testcase);
    entry = testcase;

    ft_malloc(in_len, input);
    memset(input, 0x00, in_len);
    memcpy(input, data, in_len);

    // If starting from a non-zero offset, retroactively apply the flips
    // that should have already happened.
    if(offset > 0){
        for(i = 0; i < offset; i++)
            FLIP_BIT(input, i);
    }

    for(i = 0; i < count; i++){
        ft_malloc(in_len, output);
        memset(output, 0x00, in_len);
        memcpy(output, input, in_len);

        if(i > 0){
            ft_malloc(sizeof(struct testcase),entry->next);
            entry = entry->next;
        }

        FLIP_BIT(output, i+offset);

        entry->len = in_len;
        entry->data = output;
    }

    entry->next = 0;

    free(input);
    return testcase;
}

// load all testcases from dir into a linked list
struct testcase * load_testcases(char * path, char * prefix){
    int i = 0;
    struct testcase * testcase, * entry;

    ft_malloc(sizeof(struct testcase), testcase);
    entry = testcase;

    DIR * dir;
    struct dirent *ents;
    if((dir = opendir(path)) == NULL){
        fatal("[!] Error: Could not open directory: %s\n", strerror(errno));
    }

    while ((ents = readdir(dir)) != NULL){
        // The below assumes a filesystem that supports returning types in dirent structs.
        if(strncmp(ents->d_name, prefix, strlen(prefix)) != 0 || ents->d_type != DT_REG)
            continue;

        FILE * fp;
        char file_path[PATH_MAX];

        snprintf(file_path, PATH_MAX, "%s/%s", path, ents->d_name);
        if((fp = fopen(file_path, "r"))== NULL){
            fatal("[!] Error: Could not open file %s: %s\n", file_path, strerror(errno));
        }

        if (fseek(fp, 0L, SEEK_END) == 0) {
            long bufsize = ftell(fp);
            if (bufsize == -1){
                fatal("[!] Error with ftell: %s", strerror(errno));
            }
            else if(bufsize == 0){ // handle empty file
                fclose(fp);
                continue;
            }

            if(i>0){
                // not the first entry
                ft_malloc(sizeof(struct testcase), entry->next);
                entry = entry->next;
            }
            entry->len = bufsize;

            // Go back to the start of the file.
            if (fseek(fp, 0L, SEEK_SET) != 0){
                fatal("[!] Error: could not fseek: %s\n", strerror(errno));
            }

            // Read the entire file into memory.
            ft_malloc(entry->len, entry->data);
            fread(entry->data, sizeof(char), entry->len, fp);
            if ( ferror( fp ) != 0 ){
                fatal("[!] Error: fread: %s\n", strerror(errno));
            }
        }
        fclose(fp);
        i++;
    }

    entry->next = 0; // end of the list
    closedir(dir);

    if(i == 0){ // no cases found
        memset(testcase, 0x00, sizeof(struct testcase));
    }

    return testcase; // place holder
}

// save testcase struct to disk. Returns the number of items saved or <0 on error
int save_testcases(struct testcase * cases, char * path){
    struct testcase * entry;
    entry = cases;
    int i = 1;
    char filename[PATH_MAX];

    // Use the PID as the prefix for generation
    char prefix[25];
    sprintf(prefix,"%d",(int)syscall(SYS_gettid));

    while(entry){
        snprintf(filename, PATH_MAX, "%s-%d", prefix, i);
        save_case_p(entry->data, entry->len, filename, path);
        entry = entry->next;
        i++;
    }

    return i;
}

void save_case(char * data, unsigned long len, uint32_t hash, char * directory){
    int fd;
    ssize_t w;
    char path[PATH_MAX];

    snprintf(path, PATH_MAX, "%s/%u", directory, hash);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if(fd < 0){
        if(errno == EEXIST){
            // the filename is a hash of the execution hash, so if it exists we already have it!
            printf("[!] File %s already exists, ignoring\n", path);
            close(fd);
            return;
        }
        else{
            fatal("[!] Could not open file %s: %s", path, strerror(errno));
        }
    }

    w = write(fd, data, len);

    if(w < 0){
        fatal("[!] write failed: %s", strerror(errno));
    }
    close(fd);
}

int save_case_p(char * data, unsigned long len, char * prefix, char * directory){
    int fd;
    ssize_t w;
    char path[PATH_MAX];

    snprintf(path, PATH_MAX, "%s/%s", directory, prefix);
    fd = open(path, O_WRONLY | O_CREAT, 0644);
    if(fd < 0){
        fatal("[!] Could not open file %s: %s", path, strerror(errno));
    }

    w = write(fd, data, len);
    if(w < 0){
        fatal("[!] write failed: %s", strerror(errno));
    }
    close(fd);

    return 0;
}

void free_testcases(struct testcase * cases){
    struct testcase * entry;
    entry = cases;

    while(entry){
        cases = entry->next;
        free(entry->data);
        free(entry);
        entry = cases;
    }
}
