# Fuzzotron
Fuzzotron is a simple network fuzzer supporting TCP, UDP and multithreading. Radamsa and Blab are used for test case generation. Fuzzotron exists as a first-port-of-call network fuzzer, aiming for low setup overhead.

## Install
You need to install some dependencies and at the very least Radamsa (https://gitlab.com/akihe/radamsa). Compiling targets with Address Sanitizer is also useful (https://clang.llvm.org/docs/AddressSanitizer.html)

```
apt install libssl-dev libpcre3-dev
make
```

## Usage

```
FuzzoTron - A Fuzzing Harness built around OUSPG's Blab and Radamsa.

Usage (crash-detect mode - blab): ./fuzzotron --blab -g http_request -h 127.0.0.1 -p 80 -P tcp -o output
Usage (crash-detect mode - radamsa): ./fuzzotron --radamsa --directory testcases/ -h 127.0.0.1 -p 80 -P tcp -o output
Usage (log-monitor mode): ./fuzzotron --blab -g http_request -h 127.0.0.1 -p 80 -P tcp -m /var/log/messages -r 'segfault' -o output
Usage (process-monitor mode): ./fuzzotron --radamsa --directory testcases/ -h 127.0.0.1 -p 80 -P tcp -c 23123 -o output

Generation Options:
	--blab		Use Blab for testcase generation
	-g		Blab grammar to use
	--radamsa	Use Radamsa for testcase generation
	--directory	Directory with original test cases

Connection Options:
	-h		IP of host to connect to REQUIRED
	-k		Number of seconds before fuzzing stops
	-p		Port to connect to REQUIRED
	-P		Protocol to use (tcp,udp) REQUIRED
	--ssl		Use SSL for the connection
	--destroy	Use TCP_REPAIR mode to immediately destroy the connection, do not send FIN/RST.Monitoring Options:
	-c		PID to check - Fuzzotron will halt if this PID dissapears
	-m		Logfile to monitor
	-r		Regex to use with above logfile
	-t		Number of worker threads
	-z		Check script to execute. Should return 1 on server being okay and anything else otherwise.
	--trace		Use AFL style tracing. Single threaded only, see README.md
```

Basic fuzzotron usage would look like:

```
./fuzzotron --radamsa --directory testcases -h 127.0.0.1 -p 8080 -P tcp -c 15634 -o crashes
```

The above will use radamsa to generate test cases based on the files in the 'testcases' directory, and fire these test cases at 8080/tcp on localhost. In the event that PID 15634 goes away, fuzzing will stop and the last 100 test cases kept in the output directory. This would be used for something like nginx, running with a single worker and the workers PID being specified. Without a PID specified, Fuzzotron will keep running until a connection failure occurs, indicating the port is down. Fuzzotron currently does not automatically respawn the target after a crash is detected. The '-o' flag specifies the directory to spool the current test cases out to in the event of a crash.

When a crash occurs, the test case queues for each thread will be stored in \<output dir\>/\<thread pid\>-\<testcaseno\>. The replay utility can be used to send individual test cases. Replay uses the same sender code as fuzzotron, so anything you've put into callback.c will also be triggered by replay.
```
for i in $(find output/ -type f); do replay -h <target> -p <port> -P <tcp/udp> $i; done
```

Given the nature of daemon fuzzing, running a rolling tcpdump is good insurance. Worse comes to worst, you can carve the test cases out of the PCAP and replay them manually. For example, a tcpdump command that will capture packets into a 10MB file, and capture a maximum of 10 files, would be executed as such (adding your own filter so you only catch fuzzing relevant packets is a good idea):

```
tcpdump -i ens33 -C 10M -W 10 -w out.pcap
```

### UDP fuzzing
UDP fuzzing requires some method of determining if the target is down, as the connection should never fail (yay UDP). If you're fuzzing a daemon running on localhost (recommended), then use the '-c' option and specify a PID. If the daemon is remote, fuzzotron supports the use of an auxiliary check script (--check or -z). The script needs to output '1' as its first character on success, any anything else on failure.

An example to fuzz something like, I dunno, a DHCP server running on a router, would be:

```
./fuzzotron --radamsa --directory ~/testcase-archive/network-services/dhcp-client -h 192.168.1.1 -p 67 -P udp -z ./is-dhcp-up.py -o output
```

### TCP_REPAIR mode
Specifying the --destroy flag will put the TCP connections into TCP\_REPAIR mode before closing, meaning no FIN packets will get sent. TCP\_REPAIR requires the CAP\_NET\_ADMIN capability. If --destroy ends up stalling, you may have identified a slowloris style DOS condition where the target is blocking waiting for more data.

## Connection Setup and Teardown
Sometimes some things need to happen with a connection prior to your fuzz testcase being sent. EG, if you need to send a 'hello' packet, and receive a response prior to sending your payload. Sometimes things also need to happen after the testcase is sent, like sending the 'actually-do-the-work-now-FFS' packet. callback.c defines two methods that you can modify to achieve this. The callback\_pre\_send() method also allows you to tamper the testcase before its sent, so one can implement things like packet checksumming. 

## Generators
Currently, radamsa and blab are supported for testcase generation. Radamsa takes a directory that has valid test cases and performs mutations on the provided test cases. Blab takes a grammar file which is used to programmatically generate the cases. Detailed documentation is available on their respective github pages - (https://github.com/aoh/radamsa) and (https://github.com/aoh/blab)

Fuzzotron generates test cases in batches of 100 and stores them in /dev/shm/fuzzotron/\<thread pid\>-\<number\>. Given we don't have granular visibility of exactly what case may have caused a crash (eg, you send 5 cases, case number 3 causes some long running thing to happen that results in a heap overflow (like heap exhaustion or something), server crashes at case number 5 but that's not the one that triggered the issue...), this means more manual triage. Upon detecting a crash, the latest queues for all threads are spooled to the output directory specified via a getopt argument.

### Deterministic fuzzing
Radamsa appears to be a bit overzealous with its mutations. A deterministic step has been introduced when using --radamsa mode, which will perform a walking bit mutation prior to moving to radamsa for fuzzing.

## AFL style tracing
Fuzzotron can use the coverage data provided by a target compiled with afl-gcc et-al. You need to create the SysV shared memory segment that the application will use and then pass this to both the target application and fuzzotron. As network services can be rather non-deterministic, each case on a new path is fired multiple times and only saved if it behaves deterministically, otherwise it's jettisoned. Currently tracing is only supported if you're running a single fuzzotron thread. This is all pretty sketchy and I wouldn't rely on it...

After your program is compiled, you would need to do the following. I suggest using afl-clang-fast (llvm mode...) as it plays nicer with multi-threaded targets.

```
$ ipcmk -M 65536
Shared memory id: 118718481
$ __AFL_SHM_ID=118718481 ./targetd

# in a separate session
$ ./fuzzotron --radamsa --directory <test-case-dir> -o <output dir> -h 127.0.0.1 -p <port> -P tcp --trace 118718481
```

As new solid paths are found, these will be saved in the test-case directory provided.

### Attention Deficit Fuzzing
If a new path is found, then deterministic operations are performed against this path immediately. This is mainly due to fuzzotron having no concept of an input-test-case-queue at this point.

### Testcase Discovery Mode
Using blab plus AFL style tracing is supported. Fuzzotron will save any generated testcases that trip a new path into the directory specified by --directory. This can be useful for generating a set of starting testcases to seed a mutational fuzzer (eg, radamsa mode).

## Random Musings
Something something smart fuzzing seems simple but can get hard fast, instrumentation is important, testcases and mutations and so forth. Fuzzing daemons can be a right pain in the arse, but in general it seems that having your cores spinning away with a dumb fuzzer like fuzzotron while you're coding your AI based protocol specific monstrosity can net some interesting crashes. Setup is intended to be relatively fast and easy, so why not right?

## Linux Tunables
If you run fuzzotron, especially against localhost services, you will likely find that fuzzotron can fire requests and connections faster than linux can clean them up on close(). The following sysctl tunables should be set to minimize the impact of this:

```
sysctl -w net.ipv4.tcp_tw_recycle=1
sysctl -w net.ipv4.tcp_tw_reuse=1
```

If you are using the PID monitor to check for crashes, the fuzzer will automatically resume on a failed connect. This is useful for servers that have bugs or test cases that will lock them up for a while.

```
sysctl -w net.ipv4.tcp_syn_retries=1
```
## Common Troubleshooting
* Multiple 'connection refused' errors looping - If you're providing a PID to check, then confirm that the socket is still listening. The monitored PID may still exist but the listening socket could be dead.
* Fuzzotron is stalling! - check the above linux tunables, make sure they're set
* No paths using --trace mode - confirm that your target is compiled with afl-gcc, and that the SHM number is correct

## Acknowledgments
* lcamtuf - Chunks of code and a number of core concepts from lcamtuf's AFL were used in this code base.
* VT - Testing, contributing, being the OG renegade master.
