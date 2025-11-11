#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "benchmark.h" // Use quotes for local header

struct timespec time_start, time_end;
long mem_start, mem_end;

long get_memory_usage_kb(void) {
    /* Function to benchmark memory usage */
    FILE *fp = fopen("/proc/self/statm", "r");
    if (!fp)
        return -1;
    long size, resident;
    // We only need resident set size (RSS) for actual physical memory used
    // statm format: size resident shared text lib data ...
    fscanf(fp, "%ld %ld", &size, &resident);
    fclose(fp);
    long page_size_kb = sysconf(_SC_PAGESIZE) / 1024;
    return resident * page_size_kb;
}

void measure_start_time() { clock_gettime(CLOCK_MONOTONIC, &time_start); }

void measure_end_time() { clock_gettime(CLOCK_MONOTONIC, &time_end); }

void measure_start_mem() { mem_start = get_memory_usage_kb(); }

void measure_end_mem() { mem_end = get_memory_usage_kb(); }

void benchmark_start() {
    printf("[*] Benchmark start\n");
    measure_start_time();
    measure_start_mem();
}

void benchmark_end() {
    measure_end_time();
    measure_end_mem();
    printf("[*] Benchmark end\n");
}

void benchmark_report() {
    printf("[*] Benchmark report\n");

    /* Calculate execution time */
    double execution_time = (time_end.tv_sec - time_start.tv_sec) +
                            (time_end.tv_nsec - time_start.tv_nsec) / 1e9;

    /* Print benchmark */
    printf("[*] Execution time: %.6f seconds\n", execution_time);
    printf("[*] Memory used: %ld KB -> %ld KB (delta %ld KB)\n", mem_start,
           mem_end, mem_end - mem_start);
}
