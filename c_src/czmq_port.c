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

#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "erl_interface.h"
#include "vector.h"

typedef unsigned char byte;

#define SUCCESS 0

#define REPLY_OK "ok"
#define REPLY_ERROR "error"

#define EXIT_OK 0
#define EXIT_PORT_READ_ERROR 253
#define EXIT_INTERNAL_ERROR 254

#define CMD_BUF_SIZE 10240
#define REPLY_BUF_SIZE 10240

ETERM *ETERM_PONG;
ETERM *ETERM_ZERO;

typedef struct {
    byte reply_buf[REPLY_BUF_SIZE];
} state;

typedef struct {
    ETERM *pattern;
    void (*handler)(ETERM*, state*);
} cmd_handler;

static int read_exact(byte *buf, int len)
{
    int i, got = 0;

    do {
        if ((i = read(0, buf + got, len - got)) <= 0)
            return i;
        got += i;
    } while (got < len);

    return len;
}

static int read_cmd(int max, byte *buf)
{
    int len;

    if (read_exact(buf, 2) != 2)
        return -1;
    len = (buf[0] << 8) | buf[1];
    if (len > max) {
        fprintf(stderr, "command length (%u) > max buf length (%u)", len, max);
        exit(EXIT_INTERNAL_ERROR);
    }
    return read_exact(buf, len);
}

static int write_exact(byte *buf, int len)
{
    int i, wrote = 0;

    do {
        if ((i = write(1, buf + wrote, len - wrote)) <= 0)
            return (i);
        wrote += i;
    } while (wrote < len);

    return len;
}

static int write_cmd(byte *buf, int len)
{
    byte li;

    li = (len >> 8) & 0xff;
    write_exact(&li, 1);
    li = len & 0xff;
    write_exact(&li, 1);
    return write_exact(buf, len);
}

static int safe_erl_encode(ETERM *term, int buf_size, byte *buf) {
    int term_len, encoded_len;

    if ((term_len = erl_term_len(term)) > buf_size) {
        fprintf(stderr, "term_len %u > buf_size %u", term_len, buf_size);
        exit(EXIT_INTERNAL_ERROR);
    }

    if ((encoded_len = erl_encode(term, buf)) != term_len) {
        fprintf(stderr, "bad result from erl_encode %u, expected %u",
               term_len, encoded_len);
        exit(EXIT_INTERNAL_ERROR);
    }

    return encoded_len;
}

static void write_term(ETERM *term, state *state) {
    int len = safe_erl_encode(term, REPLY_BUF_SIZE, state->reply_buf);
    write_cmd(state->reply_buf, len);
}

static void handle_ping(ETERM *term, state *state) {
    write_term(ETERM_PONG, state);
}

static void handle_poll(ETERM *term, state *state) {
    write_term(ETERM_ZERO, state);
}

static void handle_cmd(byte *buf, state *state, int handler_count,
                       cmd_handler *handlers) {
    ETERM *term;
    int i, handled = 0;

    term = erl_decode(buf);

    for (i = 0; !handled && i < handler_count; i++) {
        if (erl_match(handlers[i].pattern, term)) {
            handlers[i].handler(term, state);
            handled = 1;
        }
    }

    if (!handled) {
        fprintf(stderr, "unhandled command: ");
        erl_print_term(stderr, term);
        fprintf(stderr, "\n");
        exit(EXIT_INTERNAL_ERROR);
    }

    erl_free_compound(term);
}

int loop() {
    int HANDLER_COUNT = 2;
    cmd_handler handlers[HANDLER_COUNT];
    handlers[0].pattern = erl_format("ping");
    handlers[0].handler = &handle_ping;
    handlers[1].pattern = erl_format("poll");
    handlers[1].handler = &handle_poll;

    state state;
    int cmd_len;
    byte cmd_buf[CMD_BUF_SIZE];

    while (1) {
        cmd_len = read_cmd(CMD_BUF_SIZE, cmd_buf);
        if (cmd_len == 0) {
            exit(EXIT_OK);
        } else if (cmd_len < 0) {
            exit(EXIT_PORT_READ_ERROR);
        } else {
            handle_cmd(cmd_buf, &state, HANDLER_COUNT, handlers);
        }
    }

    return 0;
}

int test() {
    printf("Testing erlang-czmq\n");
    vector_test();
    return 0;
}

void init_eterms() {
    ETERM_PONG = erl_format("pong");
    ETERM_ZERO = erl_format("0");
}

int main(int argc, char *argv[]) {
    erl_init(NULL, 0);
    init_eterms();
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        return test();
    } else {
        return loop();
    }
}
