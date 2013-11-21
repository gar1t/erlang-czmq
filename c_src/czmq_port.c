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

#include "czmq.h"
#undef ETERM // collision between zmq.h and erl_interface.h
#include "erl_interface.h"
#include "vector.h"

#define SUCCESS 0

#define REPLY_OK "ok"
#define REPLY_ERROR "error"

#define EXIT_OK 0
#define EXIT_PORT_READ_ERROR 253
#define EXIT_INTERNAL_ERROR 254

#define CMD_BUF_SIZE 10240
#define REPLY_BUF_SIZE 10240

#define MAX_SOCKETS 999999

#define assert_tuple_size(term, size) \
    assert(ERL_IS_TUPLE(term)); \
    assert(erl_size(term) == size)

typedef unsigned char byte;

typedef struct {
    byte reply_buf[REPLY_BUF_SIZE];
    zctx_t *ctx;
    vector sockets;
} state;

typedef void (*cmd_handler)(ETERM*, state*);

ETERM *ETERM_CMD_PATTERN;
ETERM *ETERM_OK;
ETERM *ETERM_UNDEFINED;
ETERM *ETERM_TODO;
ETERM *ETERM_PONG;
ETERM *ETERM_ERROR_INVALID_SOCKET;
ETERM *ETERM_ERROR_BIND_FAILED;
ETERM *ETERM_ERROR_CONNECT_FAILED;

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

static void handle_ping(ETERM *args, state *state) {
    write_term(ETERM_PONG, state);
}

static int save_socket(void *socket, state *state) {
    int i;
    for (i = 0; i < MAX_SOCKETS; i++) {
        if (!vector_get(&state->sockets, i)) {
            vector_set(&state->sockets, i, socket);
            return i;
        }
    }
    assert(0);
}

static void handle_zsocket_new(ETERM *args, state *state) {
    assert_tuple_size(args, 1);
    ETERM *type_arg = erl_element(1, args);
    int type = ERL_INT_VALUE(type_arg);

    void *socket = zsocket_new(state->ctx, type);
    assert(socket);

    int index = save_socket(socket, state);
    ETERM *index_term = erl_mk_int(index);
    write_term(index_term, state);
    erl_free_term(index_term);
}

static void *get_socket(int index, state *state) {
    return vector_get(&state->sockets, index);
}

static void handle_zsocket_bind(ETERM *args, state *state) {
    assert_tuple_size(args, 2);
    ETERM *socket_id_arg = erl_element(1, args);
    ETERM *endpoint_arg = erl_element(2, args);

    int socket_id = ERL_INT_VALUE(socket_id_arg);
    void *socket = get_socket(socket_id, state);
    if (!socket) {
        write_term(ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    char *endpoint = erl_iolist_to_string(endpoint_arg);
    int rc = zsocket_bind(socket, endpoint);
    if (rc == -1) {
        write_term(ETERM_ERROR_BIND_FAILED, state);
        return;
    }

    ETERM *result = erl_format("{ok,~i}", rc);
    write_term(result, state);

    erl_free(endpoint);
    erl_free_term(result);
}

static void handle_zsocket_connect(ETERM *args, state *state) {
    assert_tuple_size(args, 2);
    ETERM *socket_id_arg = erl_element(1, args);
    ETERM *endpoint_arg = erl_element(2, args);

    int socket_id = ERL_INT_VALUE(socket_id_arg);
    void *socket = get_socket(socket_id, state);
    if (!socket) {
        write_term(ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    char *endpoint = erl_iolist_to_string(endpoint_arg);
    int rc = zsocket_connect(socket, endpoint);
    if (rc == -1) {
        write_term(ETERM_ERROR_CONNECT_FAILED, state);
        return;
    }

    write_term(ETERM_OK, state);

    erl_free(endpoint);
}

static void handle_zstr_send(ETERM *args, state *state) {
    assert_tuple_size(args, 2);
    ETERM *socket_id_arg = erl_element(1, args);
    ETERM *data_arg = erl_element(2, args);

    int socket_id = ERL_INT_VALUE(socket_id_arg);
    void *socket = get_socket(socket_id, state);
    if (!socket) {
        write_term(ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    char *data = erl_iolist_to_string(data_arg);
    zstr_send(socket, data);

    write_term(ETERM_OK, state);

    erl_free(data);
}

static void handle_zstr_recv_nowait(ETERM *args, state *state) {
    assert_tuple_size(args, 1);
    ETERM *socket_id_arg = erl_element(1, args);

    int socket_id = ERL_INT_VALUE(socket_id_arg);
    void *socket = get_socket(socket_id, state);
    if (!socket) {
        write_term(ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    char *data = zstr_recv_nowait(socket);
    
    if (data) {
        ETERM *result = erl_format("{ok,~s}", data);
        write_term(result, state);
        erl_free_term(result);
        free(data);
    } else {
        write_term(ETERM_UNDEFINED, state);
    }
}

static void handle_cmd(byte *buf, state *state, int handler_count,
                       cmd_handler *handlers) {
    ETERM *cmd_term = erl_decode(buf);
    if (!erl_match(ETERM_CMD_PATTERN, cmd_term)) {
        fprintf(stderr, "invalid cmd format: ");
        erl_print_term(stderr, cmd_term);
        fprintf(stderr, "\n");
        exit(EXIT_INTERNAL_ERROR);
    }

    ETERM *cmd_id_term = erl_element(1, cmd_term);
    int cmd_id = ERL_INT_VALUE(cmd_id_term);
    if (cmd_id < 0 || cmd_id >= handler_count) {
        fprintf(stderr, "cmd_id out of range: %i", cmd_id);
        exit(EXIT_INTERNAL_ERROR);
    }

    ETERM *cmd_args_term = erl_element(2, cmd_term);
    handlers[cmd_id](cmd_args_term, state);

    erl_free_compound(cmd_term);
    erl_free_compound(cmd_id_term);
    erl_free_compound(cmd_args_term);
}

static int loop(state *state) {
    int HANDLER_COUNT = 6;
    cmd_handler handlers[HANDLER_COUNT];
    handlers[0] = &handle_ping;
    handlers[1] = &handle_zsocket_new;
    handlers[2] = &handle_zsocket_bind;
    handlers[3] = &handle_zsocket_connect;
    handlers[4] = &handle_zstr_send;
    handlers[5] = &handle_zstr_recv_nowait;

    int cmd_len;
    byte cmd_buf[CMD_BUF_SIZE];

    while (1) {
        cmd_len = read_cmd(CMD_BUF_SIZE, cmd_buf);
        if (cmd_len == 0) {
            exit(EXIT_OK);
        } else if (cmd_len < 0) {
            exit(EXIT_PORT_READ_ERROR);
        } else {
            handle_cmd(cmd_buf, state, HANDLER_COUNT, handlers);
        }
    }

    return 0;
}

static int test() {
    printf("Testing erlang-czmq\n");
    vector_test();
    return 0;
}

static void init_eterms() {
    ETERM_CMD_PATTERN = erl_format("{_,_}");
    ETERM_OK = erl_format("ok");
    ETERM_UNDEFINED = erl_format("undefined");
    ETERM_TODO = erl_format("todo");
    ETERM_PONG = erl_format("pong");
    ETERM_ERROR_INVALID_SOCKET = erl_format("{error,invalid_socket}");
    ETERM_ERROR_BIND_FAILED = erl_format("{error,bind_failed}");
    ETERM_ERROR_CONNECT_FAILED = erl_format("{error,connect_failed}");
}

static void init_state(state *state) {
    state->ctx = zctx_new();
    assert(state->ctx);
    vector_init(&state->sockets);
}

int main(int argc, char *argv[]) {
    state state;

    erl_init(NULL, 0);
    init_eterms();
    init_state(&state);

    int ret;

    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        ret = test();
    } else {
        ret = loop(&state);
    }

    return ret;
}
