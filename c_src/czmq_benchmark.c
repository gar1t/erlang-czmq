// Copyright (C) 2012, 2013 Garrett Smith <g@rre.tt>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifdef __MACH__
#include <mach/mach_time.h>
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 0
int clock_gettime(int clk_id, struct timespec *t){
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t time;
    time = mach_absolute_time();
    double nseconds = ((double)time * (double)timebase.numer)/((double)timebase.denom);
    double seconds = ((double)time * (double)timebase.numer)/((double)timebase.denom * 1e9);
    t->tv_sec = seconds;
    t->tv_nsec = nseconds;
    return 0;
}
#else
#include <time.h>
#endif

#include "czmq.h"

#define default_port 5555
#define default_time 5
#define default_msg_size 512
#define default_send_socket_type ZMQ_PUSH;
#define default_recv_socket_type ZMQ_PULL;

typedef struct {
    uint port;
    uint time;
    int socket_type;
    ulong msg_size;
} benchmark_options;

static void print_usage() {
    printf("Usage: czmq-benchmark [OPTION] COMMAND\n");
    printf("\n");
    printf("Commands:\n");
    printf("  send         send messages to PORT for TIME seconds\n");
    printf("  recv         receive messages on PORT for TIME seconds\n");
    printf("\n");
    printf("Options:\n");
    printf("  -p PORT      port to send to / listen on (default is %i)\n",
           default_port);
    printf("  -t TIME      seconds to sendfor (default is %i)\n",
           default_time);
    printf("  -s MSG_SIZE  message size in bytes (default is %i)\n",
           default_msg_size);
    printf("  -h           print this message and exit\n");
}

static char rand_char() {
    // printable ascii range: 32 - 126 (94 chars)
    //int rand94 = 94 * (rand() / (RAND_MAX + 1.0));
    //return (char)(32 + rand94);
    return '!';   // temp simplification to work around segfault 
                  // for large strings (related to getting string len)
}

static char *create_message(ulong size) {
    char *msg = malloc(size + 1);
    ulong i;
    for (i = 0; i < size; i++) {
        msg[i] = rand_char();
    }
    msg[size] = '\0';
    return msg;
}

static long now_ms() {
    struct timespec spec;
    int rc = clock_gettime(CLOCK_REALTIME, &spec);
    assert(rc == 0);
    return spec.tv_sec * 1000 + (spec.tv_nsec / 1.0e6);
}

static void send_messages(benchmark_options *options) {
    zctx_t *ctx = zctx_new();
    assert (ctx);

    void *socket = zsocket_new(ctx, options->socket_type);
    assert(socket);
    int rc = zsocket_connect(socket, "tcp://localhost:%i", options->port);
    assert(rc == 0);

    char *msg = create_message(options->msg_size);

    long now = now_ms();
    long stop = now + options->time * 1000;

    while (now < stop) {
        zstr_send(socket, msg);
        now = now_ms();
    }

    free(msg);

    sleep(1);
    zctx_destroy(&ctx);
}

static int recv_loop;

static void stop_recv(int sig) {
    recv_loop = 0;
}

static void recv_messages(benchmark_options *options) {
    zctx_t *ctx = zctx_new();
    assert (ctx);

    void *socket = zsocket_new(ctx, options->socket_type);
    assert(socket);
    int rc = zsocket_bind(socket, "tcp://*:%i", options->port);
    if (rc == -1) {
        printf("Error binding to port %i\n", options->port);
        exit(1);
    }

    long last_log = now_ms(), now;
    int msg_count = 0;
    char *msg;

    recv_loop = 1;
    signal(SIGINT, stop_recv);

    while (recv_loop) {
        now = now_ms();
        if (now - last_log >= 1000) {
            printf("%li %i\n", now, msg_count);
            last_log = now;
            msg_count = 0;
        }
        while (1) {
            msg = zstr_recv_nowait(socket);
            if (!msg) {
                break;
            }
            msg_count++;
            free(msg);
        }
        usleep(100);
    }

    sleep(1);
    zctx_destroy(&ctx);
}

int main(int argc, char *argv[]) {
    char *port_arg = NULL;
    char *time_arg = NULL;
    char *msg_size_arg = NULL;
    int c;

    while ((c = getopt (argc, argv, "hp:t:s:")) != -1)
        switch (c)
            {
            case 'h':
                print_usage();
                return 0;
            case 'p':
                port_arg = optarg;
                break;
            case 't':
                time_arg = optarg;
                break;
            case 's':
                msg_size_arg = optarg;
                break;
            default:
                print_usage();
                return 1;
            }

    if (optind != (argc - 1)) {
        print_usage();
        return 1;
    }

    char *cmd_arg = argv[optind];

    benchmark_options options;
    uint int_val;
    ulong long_val;

    // port
    if (port_arg) {
        if (sscanf(port_arg, "%u", &int_val) != 1) {
            printf("Invalid port value %s\n", port_arg);
            return 1;
        }
        options.port = int_val;
    } else {
        options.port = default_port;
    }

    // time
    if (time_arg) {
        if (sscanf(time_arg, "%u", &int_val) != 1) {
            printf("Invalid time value %s\n", time_arg);
            return 1;
        }
        options.time = int_val;
    } else {
        options.time = default_time;
    }

    // msg_size
    if (msg_size_arg) {
        if (sscanf(msg_size_arg, "%lu", &long_val) != 1) {
            printf("Invalid msg size value %s\n", msg_size_arg);
            return 1;
        }
        options.msg_size = long_val;
    } else {
        options.msg_size = default_msg_size;
    }

    if (strcmp(cmd_arg, "send") == 0) {
        options.socket_type = default_send_socket_type;
        send_messages(&options);
        return 0;
    } else if (strcmp(cmd_arg, "recv") == 0) {
        options.socket_type = default_recv_socket_type;
        recv_messages(&options);
        return 0;
    } else {
        print_usage();
        return 1;
    }

    printf("port_arg = %s, time_arg = %s, cmd = %s\n",
           port_arg, time_arg, cmd_arg);

    return 0;
}
