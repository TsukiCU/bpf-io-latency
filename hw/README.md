# IOLatency eBPF Program
## Overview
This demo is to monitor and measure the latency of block I/O requests in Linux systems, and output a histogram of I/O requests latencies.

The output histogram is printed regularly, and the interval between each print is determined by user.
```shell
     usecs               : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 1        |***                                     |
       128 -> 255        : 1        |***                                     |
       256 -> 511        : 5        |****************                        |
       512 -> 1023       : 2        |******                                  |
      1024 -> 2047       : 12       |****************************************|
      2048 -> 4095       : 6        |********************                    |
      4096 -> 8191       : 6        |********************                    |
```

## Features
* **Latency Measurement**: Capture the latency of block I/O requests in microseconds.
* **Histogram Display**: Present latency distribution in a histogram for easy analysis.
* **Low Overhead**: Designed to minimize impact on system performance while providing accurate latency metrics.
* **Dynamic Tracing**: No need to modify or recompile the kernel to deploy iolatency(we are using ebpf so of course..)

## Testing environment
This program was tested under the following environment:

- **Operating System**: Debian GNU/Linux
- **Kernel Version**: 6.1.0-13-amd64
- **Architecture**: x86_64

## Prerequisites
* **Kernel Version**: 4.9 or newer with eBPF support enabled.
* **LLVM/Clang**: Version 6.0 or newer for compiling the eBPF program.
* **libbpf**: Required for the user space program to interact with eBPF.
* **Root Access**: Required for loading eBPF programs into the kernel.

## Installation
Clone the Repository
make
```shell
make
```

and run with sudo.

```shell
sudo ./iolatency n
```

**n** refers to the interval between printing histograms.

## Testing Overview
**The testing results are in `./test_output`.**

Below, you will find detailed instructions on how to execute the tests,
along with a brief description of each component involved in the testing process.
+ **test.fio**

This is a test fio configuration file to generate intensive I/O requests. Run by
```shell
  fio test.fio
```
+ **reference.sh**

This is a reference script available under the GNU General Public License (http://www.gnu.org/copyleft/gpl.html).
It also measures I/O request latencies and presents the results in a histogram format for easy analysis.

### Comparative Testing

The performance were tested following these steps.
1. Execute both reference.sh and the iolatency tool in parallel.
2. While these tools are running, start the test.fio to generate I/O requests.
3. Record the output of reference.sh in reference_results.txt.
4. Similarly, capture the output of iolatency in iolatency_results.txt.

### Analysis

Upon reviewing the outputs (reference_results.txt and iolatency_results.txt), it was observed that the results are very similar,
indicating a high level of accuracy and reliability in our iolatency tool's measurements compared to the established reference.

  
