/*  =========================================================================
    erl_czmq - General functions for czmq_port

    -------------------------------------------------------------------------
    Copyright (c) 2013-214 Garrett Smith <g@rre.tt>
    Copyright other contributors as noted in the AUTHORS file.

    This file is part of erlang-czmq: https://github.com/gar1t/erlang-czmq

    This is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by the
    Free Software Foundation; either version 3 of the License, or (at your
    option) any later version.

    This software is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABIL-
    ITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
    Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
    =========================================================================
*/

#include "czmq.h"

#undef ETERM // collision between zmq.h and erl_interface.h

#include "erl_interface.h"
#include "erl_czmq.h"
#include "ev.h"

ETERM *ETERM_OK;
ETERM *ETERM_UNDEFINED;
ETERM *ETERM_TRUE;
ETERM *ETERM_FALSE;
ETERM *ETERM_PONG;
ETERM *ETERM_ERROR;
ETERM *ETERM_ERROR_INVALID_CMD;
ETERM *ETERM_ERROR_INVALID_SOCKET;
ETERM *ETERM_ERROR_BIND_FAILED;
ETERM *ETERM_ERROR_UNBIND_FAILED;
ETERM *ETERM_ERROR_CONNECT_FAILED;
ETERM *ETERM_ERROR_DISCONNECT_FAILED;
ETERM *ETERM_ERROR_INVALID_AUTH;
ETERM *ETERM_ERROR_INVALID_CERT;

#define ZCTX_SET_IOTHREADS 0
#define ZCTX_SET_LINGER 1
#define ZCTX_SET_PIPEHWM 2
#define ZCTX_SET_SNDHWM 3
#define ZCTX_SET_RCVHWM 4

#define ZSOCKOPT_ZAP_DOMAIN 0
#define ZSOCKOPT_PLAIN_SERVER 1
#define ZSOCKOPT_PLAIN_USERNAME 2
#define ZSOCKOPT_PLAIN_PASSWORD 3
#define ZSOCKOPT_CURVE_SERVER 4
#define ZSOCKOPT_CURVE_SERVERKEY 5
#define ZSOCKOPT_BACKLOG 6
#define ZSOCKOPT_SNDHWM 7
#define ZSOCKOPT_RCVHWM 8
#define ZSOCKOPT_SUBSCRIBE 9
#define ZSOCKOPT_UNSUBSCRIBE 10
#define ZSOCKOPT_IDENTITY 11

#define SUCCESS 0
#define EXIT_OK 0
#define EXIT_PORT_READ_ERROR 253
#define EXIT_INTERNAL_ERROR 254

#define CMD_BUF_SIZE 10240
#define MAX_SOCKETS 999999
#define MAX_CERTS 999999

#define assert_tuple_size(term, size)   \
    do {                                \
        assert(ERL_IS_TUPLE(term));     \
        assert(erl_size(term) == size); \
    } while(0)

typedef void (*cmd_handler)(EV_P_ ETERM*, ETERM*);

#define ERL_ZPOLLER_REPEAT 1.0

typedef struct erl_zpoller {
    ev_timer watcher;
    zpoller_t *zpoll;
    ETERM *id;
} erl_zpoller_t;

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

static void write_term(ETERM *term, erl_czmq_state *state) {
    int len = safe_erl_encode(term, ERL_CZMQ_REPLY_BUF_SIZE, state->reply_buf);
    write_cmd(state->reply_buf, len);
}

static inline void reply(ETERM *client, ETERM *msg, erl_czmq_state *state) {
    ETERM *result[2];
    result[0] = client;
    result[1] = msg;

    ETERM *result_tuple = erl_mk_tuple(result, 2);
    write_term(result_tuple, state);

    erl_free_term(result_tuple);
} 

#define POLLER_ID_LEN 80
static char *save_poller(void *poller, erl_czmq_state *state) {
    char *key = malloc(POLLER_ID_LEN);
    if (!key)
        return NULL;
    
    sprintf(key, "%p", poller);
    int res = zhash_insert(state->pollers, key, poller);
    if (res)
        return NULL;

    return key;
}

static erl_zpoller_t *delete_poller(char *key, erl_czmq_state *state) {
    erl_zpoller_t *poller = zhash_lookup(state->pollers, key);
    if (!poller)
        return NULL;

    zhash_delete(state->pollers, key);
    return poller;
}

static int save_socket(void *socket, erl_czmq_state *state) {
    int i;
    for (i = 0; i < MAX_SOCKETS; i++) {
        if (!vector_get(&state->sockets, i)) {
            vector_set(&state->sockets, i, socket);
            return i;
        }
    }
    assert(0);
}

static void clear_socket(int socket_index, erl_czmq_state *state) {
    vector_set(&state->sockets, socket_index, NULL);
}

static int int_arg(ETERM *args, int arg_pos) {
    return ERL_INT_VALUE(erl_element(arg_pos, args));
}

static void *socket_from_arg(ETERM *args, int arg_pos, erl_czmq_state *state) {
    return vector_get(&state->sockets, int_arg(args, arg_pos));
}

static zcert_t *cert_from_arg(ETERM *args, int arg_pos, erl_czmq_state *state) {
    return vector_get(&state->certs, int_arg(args, arg_pos));
}

static void clear_cert(int cert_index, erl_czmq_state *state) {
    vector_set(&state->certs, cert_index, NULL);
}

static void handle_ping(EV_P_ ETERM *client, ETERM *args) {
    erl_czmq_state *state = ev_userdata(EV_A);
    reply(client, ETERM_PONG, state);
}

static void handle_zctx_set_int(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    ETERM *opt_arg = erl_element(1, args);
    int opt = ERL_INT_VALUE(opt_arg);

    ETERM *val_arg = erl_element(2, args);
    int val = ERL_INT_VALUE(val_arg);

    erl_czmq_state *state = ev_userdata(EV_A);
    switch(opt) {
    case ZCTX_SET_IOTHREADS:
        zctx_set_iothreads(state->ctx, val);
        break;
    case ZCTX_SET_LINGER:
        zctx_set_linger(state->ctx, val);
        break;
    case ZCTX_SET_PIPEHWM:
        zctx_set_pipehwm(state->ctx, val);
        break;
    case ZCTX_SET_SNDHWM:
        zctx_set_sndhwm(state->ctx, val);
        break;
    case ZCTX_SET_RCVHWM:
        zctx_set_rcvhwm(state->ctx, val);
        break;
    default:
        assert(0);
    }

    reply(client, ETERM_OK, state);
}

static void handle_zsocket_new(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 1);
    ETERM *type_arg = erl_element(1, args);
    int type = ERL_INT_VALUE(type_arg);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = zsocket_new(state->ctx, type);
    assert(socket);

    int index = save_socket(socket, state);
    ETERM *index_term = erl_mk_int(index);

    reply(client, index_term, state);
    erl_free_term(index_term);
}

static void handle_zsocket_type_str(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 1);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    char *type_str = zsocket_type_str(socket);
    ETERM *type_term = erl_mk_string(type_str);

    reply(client, type_term, state);
    erl_free_term(type_term);
}

static void handle_zsocket_bind(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    ETERM *endpoint_arg = erl_element(2, args);
    char *endpoint = erl_iolist_to_string(endpoint_arg);
    assert(endpoint);
    int rc = zsocket_bind(socket, endpoint);
    if (rc == -1) {
        reply(client, ETERM_ERROR_BIND_FAILED, state);
        erl_free(endpoint);
        return;
    }

    ETERM *result[2];
    result[0] = ETERM_OK;

    ETERM *rc_int = erl_mk_int(rc);
    result[1] = rc_int;

    ETERM *result_tuple = erl_mk_tuple(result, 2);
    reply(client, result_tuple, state);

    erl_free(endpoint);
    erl_free_term(rc_int);
    erl_free_term(result_tuple);
}

static void handle_zsocket_unbind(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    ETERM *endpoint_arg = erl_element(2, args);
    char *endpoint = erl_iolist_to_string(endpoint_arg);
    assert(endpoint);

    int rc = zsocket_unbind(socket, endpoint);
    if (rc == -1) {
        reply(client, ETERM_ERROR_UNBIND_FAILED, state);
        erl_free(endpoint);
        return;
    }

    reply(client, ETERM_OK, state);

    erl_free(endpoint);
}

static void handle_zsocket_connect(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    ETERM *endpoint_arg = erl_element(2, args);
    char *endpoint = erl_iolist_to_string(endpoint_arg);
    assert(endpoint);

    int rc = zsocket_connect(socket, endpoint);
    if (rc == -1) {
        reply(client, ETERM_ERROR_CONNECT_FAILED, state);
        erl_free(endpoint);
        return;
    }

    reply(client, ETERM_OK, state);

    erl_free(endpoint);
}

static void handle_zsocket_disconnect(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    ETERM *endpoint_arg = erl_element(2, args);
    char *endpoint = erl_iolist_to_string(endpoint_arg);
    assert(endpoint);

    int rc = zsocket_disconnect(socket, endpoint);
    if (rc == -1) {
        reply(client, ETERM_ERROR_DISCONNECT_FAILED, state);
        erl_free(endpoint);
        return;
    }

    reply(client, ETERM_OK, state);

    erl_free(endpoint);
}

static void handle_zsocket_sendmem(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 3);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    ETERM *data_bin_arg = erl_element(2, args);
    const void *data_bin = ERL_BIN_PTR(data_bin_arg);
    size_t data_bin_size = ERL_BIN_SIZE(data_bin_arg);

    ETERM *flags_arg = erl_element(3, args);
    int flags = ERL_INT_VALUE(flags_arg) | ZFRAME_DONTWAIT;

    int rc = zsocket_sendmem(socket, data_bin, data_bin_size, flags);
    if (rc == 0) {
        reply(client, ETERM_OK, state);
    } else {
        reply(client, ETERM_ERROR, state);
    }
}

static void handle_zsocket_destroy(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 1);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    zsocket_destroy(state->ctx, socket);
    clear_socket(int_arg(args, 1), state);

    reply(client, ETERM_OK, state);
}

static void handle_zsockopt_get_str(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    ETERM *opt_arg = erl_element(2, args);
    int opt = ERL_INT_VALUE(opt_arg);

    char* val;

    switch(opt) {
    case ZSOCKOPT_ZAP_DOMAIN:
        val = zsocket_zap_domain(socket);
        break;
    case ZSOCKOPT_PLAIN_USERNAME:
        val = zsocket_plain_username(socket);
        break;
    case ZSOCKOPT_PLAIN_PASSWORD:
        val = zsocket_plain_password(socket);
        break;
    case ZSOCKOPT_CURVE_SERVERKEY:
        val = zsocket_curve_serverkey(socket);
        break;
    case ZSOCKOPT_IDENTITY:
        val = zsocket_identity(socket);
        break;
    default:
        assert(0);
    }

    assert(val);
    ETERM *val_string = erl_mk_string(val);
    reply(client, val_string, state);

    erl_free_term(val_string);
    erl_free(val);
}

static void handle_zsockopt_get_int(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    ETERM *opt_arg = erl_element(2, args);
    int opt = ERL_INT_VALUE(opt_arg);

    int val;

    switch(opt) {
    case ZSOCKOPT_PLAIN_SERVER:
        val = zsocket_plain_server(socket);
        break;
    case ZSOCKOPT_CURVE_SERVER:
        val = zsocket_curve_server(socket);
        break;
    case ZSOCKOPT_BACKLOG:
        val = zsocket_backlog(socket);
        break;
    case ZSOCKOPT_SNDHWM:
        val = zsocket_sndhwm(socket);
        break;
    case ZSOCKOPT_RCVHWM:
        val = zsocket_rcvhwm(socket);
        break;
    default:
        assert(0);
    }

    ETERM *msg = erl_mk_int(val);
    reply(client, msg, state);

    erl_free_term(msg);
}

static void handle_zsockopt_set_str(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 3);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    ETERM *opt_arg = erl_element(2, args);
    int opt = ERL_INT_VALUE(opt_arg);

    ETERM *val_arg = erl_element(3, args);
    char *val = erl_iolist_to_string(val_arg);

    switch(opt) {
    case ZSOCKOPT_ZAP_DOMAIN:
        zsocket_set_zap_domain(socket, val);
        break;
    case ZSOCKOPT_PLAIN_USERNAME:
        zsocket_set_plain_username(socket, val);
        break;
    case ZSOCKOPT_PLAIN_PASSWORD:
        zsocket_set_plain_password(socket, val);
        break;
    case ZSOCKOPT_CURVE_SERVERKEY:
        zsocket_set_curve_serverkey(socket, val);
        break;
    case ZSOCKOPT_SUBSCRIBE:
        zsocket_set_subscribe(socket, val);
        break;
    case ZSOCKOPT_IDENTITY:
        zsocket_set_identity(socket, val);
        break;
    case ZSOCKOPT_UNSUBSCRIBE:
        zsocket_set_unsubscribe(socket, val);
        break;
    default:
        assert(0);
    }

    reply(client, ETERM_OK, state);
    erl_free(val);
}

static void handle_zsockopt_set_int(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 3);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    ETERM *opt_arg = erl_element(2, args);
    int opt = ERL_INT_VALUE(opt_arg);

    ETERM *val_arg = erl_element(3, args);
    int val = ERL_INT_VALUE(val_arg);

    switch(opt) {
    case ZSOCKOPT_PLAIN_SERVER:
        zsocket_set_plain_server(socket, val);
        break;
    case ZSOCKOPT_CURVE_SERVER:
        zsocket_set_curve_server(socket, val);
        break;
    case ZSOCKOPT_BACKLOG:
        zsocket_set_backlog(socket, val);
        break;
    case ZSOCKOPT_SNDHWM:
        zsocket_set_sndhwm(socket, val);
        break;
    case ZSOCKOPT_RCVHWM:
        zsocket_set_rcvhwm(socket, val);
        break;
    default:
        assert(0);
    }

    reply(client, ETERM_OK, state);
}

static void handle_zstr_send(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    ETERM *data_arg = erl_element(2, args);
    char *data = erl_iolist_to_string(data_arg);
    assert(data);

    int data_len = strlen(data);

    // Use zsocket_sendmem to use non-blocking send (zstr_send blocks)
    int rc = zsocket_sendmem(socket, data, data_len, ZFRAME_DONTWAIT);
    if (rc == 0) {
        reply(client, ETERM_OK, state);
    } else {
        reply(client, ETERM_ERROR, state);
    }

    erl_free(data);
}

static void handle_zstr_recv_nowait(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 1);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    char *data = zstr_recv_nowait(socket);

    if (!data) {
        reply(client, ETERM_ERROR, state);
        return;
    }

    ETERM *result[2];
    result[0] = ETERM_OK;
    ETERM *data_string = erl_mk_string(data);
    result[1] = data_string;
    ETERM *result_tuple = erl_mk_tuple(result, 2);

    reply(client, result_tuple, state);

    zstr_free(&data);
    erl_free_term(data_string);
    erl_free_term(result_tuple);
}

static void handle_zframe_recv_nowait(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 1);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    zframe_t *frame = zframe_recv_nowait(socket);
    if (!frame) {
        reply(client, ETERM_ERROR, state);
        return;
    }

    size_t frame_size = zframe_size(frame);
    byte *frame_data = zframe_data(frame);
    int more = zframe_more(frame);


    ETERM *result[2];
    result[0] = ETERM_OK;

    ETERM *sub_result[2];
    ETERM *data_bin = erl_mk_binary((char*)frame_data, frame_size);
    sub_result[0] = data_bin;
    sub_result[1] = more ? ETERM_TRUE : ETERM_FALSE;

    ETERM *sub_result_tuple = erl_mk_tuple(sub_result, 2);
    result[1] = sub_result_tuple;

    ETERM *result_tuple = erl_mk_tuple(result, 2);
    reply(client, result_tuple, state);

    zframe_destroy(&frame);
    erl_free_term(data_bin);
    erl_free_term(sub_result_tuple);
    erl_free_term(result_tuple);
}

static void set_auth(zauth_t *auth, erl_czmq_state *state) {
    assert(state->auth == NULL);
    state->auth = auth;
}

static void handle_zauth_new(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 0);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *auth = zauth_new(state->ctx);
    assert(auth);

    set_auth(auth, state);
    ETERM *mock_index_term = erl_mk_int(0); // only have one auth/ctx

    reply(client, mock_index_term, state);
    erl_free_term(mock_index_term);
}

static zauth_t *auth_from_arg(ETERM *args, int arg_pos,
                              erl_czmq_state *state) {
    ETERM *auth_arg = erl_element(arg_pos, args);
    int auth_id = ERL_INT_VALUE(auth_arg);
    // We only have one auth/state which is represented by the mock ID 0
    if (auth_id == 0) {
        return state->auth;
    } else {
        return NULL;
    }
}

static void handle_zauth_deny(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    zauth_t *auth = auth_from_arg(args, 1, state);
    if (!auth) {
        reply(client, ETERM_ERROR_INVALID_AUTH, state);
        return;
    }

    ETERM *address_arg = erl_element(2, args);
    char *address = erl_iolist_to_string(address_arg);
    assert(address);

    zauth_deny(auth, address);
    reply(client, ETERM_OK, state);

    erl_free(address);
}

static void handle_zauth_allow(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    zauth_t *auth = auth_from_arg(args, 1, state);
    if (!auth) {
        reply(client, ETERM_ERROR_INVALID_AUTH, state);
        return;
    }

    ETERM *address_arg = erl_element(2, args);
    char *address = erl_iolist_to_string(address_arg);
    assert(address);

    zauth_allow(auth, address);
    reply(client, ETERM_OK, state);

    erl_free(address);
}

static void handle_zauth_configure_plain(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 3);

    erl_czmq_state *state = ev_userdata(EV_A);
    zauth_t *auth = auth_from_arg(args, 1, state);
    if (!auth) {
        reply(client, ETERM_ERROR_INVALID_AUTH, state);
        return;
    }

    ETERM *domain_arg = erl_element(2, args);
    char *domain = erl_iolist_to_string(domain_arg);
    assert(domain);

    ETERM *pwd_file_arg = erl_element(3, args);
    char *pwd_file = erl_iolist_to_string(pwd_file_arg);
    assert(pwd_file);

    zauth_configure_plain(auth, domain, pwd_file);

    reply(client, ETERM_OK, state);

    erl_free(domain);
    erl_free(pwd_file);
}

static void handle_zauth_configure_curve(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 3);

    erl_czmq_state *state = ev_userdata(EV_A);
    zauth_t *auth = auth_from_arg(args, 1, state);
    if (!auth) {
        reply(client, ETERM_ERROR_INVALID_AUTH, state);
        return;
    }

    ETERM *domain_arg = erl_element(2, args);
    char *domain = erl_iolist_to_string(domain_arg);

    ETERM *location_arg = erl_element(3, args);
    char *location = erl_iolist_to_string(location_arg);

    zauth_configure_curve(auth, domain, location);

    reply(client, ETERM_OK, state);

    erl_free(domain);
    erl_free(location);
}

static void clear_auth(erl_czmq_state *state) {
    state->auth = NULL;
}

static void handle_zauth_destroy(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 1);

    erl_czmq_state *state = ev_userdata(EV_A);
    zauth_t *auth = auth_from_arg(args, 1, state);
    if (!auth) {
        reply(client, ETERM_ERROR_INVALID_AUTH, state);
        return;
    }

    zauth_destroy(&auth);
    clear_auth(state);

    reply(client, ETERM_OK, state);
}

static int save_cert(void *cert, erl_czmq_state *state) {
    int i;
    for (i = 0; i < MAX_CERTS; i++) {
        if (!vector_get(&state->certs, i)) {
            vector_set(&state->certs, i, cert);
            return i;
        }
    }
    assert(0);
}

static void handle_zcert_new(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 0);

    zcert_t *cert = zcert_new();
    assert(cert);

    erl_czmq_state *state = ev_userdata(EV_A);
    int index = save_cert(cert, state);
    ETERM *index_term = erl_mk_int(index);

    reply(client, index_term, state);
    erl_free_term(index_term);
}

static void handle_zcert_apply(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    zcert_t *cert = cert_from_arg(args, 1, state);
    if (!cert) {
        reply(client, ETERM_ERROR_INVALID_CERT, state);
        return;
    }

    void *socket = socket_from_arg(args, 2, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    zcert_apply(cert, socket);

    reply(client, ETERM_OK, state);
}

static void handle_zcert_public_txt(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 1);

    erl_czmq_state *state = ev_userdata(EV_A);
    zcert_t *cert = cert_from_arg(args, 1, state);
    if (!cert) {
        reply(client, ETERM_ERROR_INVALID_CERT, state);
        return;
    }

    char *txt = zcert_public_txt(cert);
    assert(txt);

    ETERM *result[2];
    ETERM *txt_term = erl_mk_string(txt);
    result[0] = ETERM_OK;
    result[1] = txt_term;

    ETERM *result_tuple = erl_mk_tuple(result, 2);
    reply(client, result_tuple, state);

    erl_free_term(txt_term);
    erl_free_term(result_tuple);
}

static void handle_zcert_save_public(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 2);

    erl_czmq_state *state = ev_userdata(EV_A);
    void *cert = cert_from_arg(args, 1, state);
    if (!cert) {
        reply(client, ETERM_ERROR_INVALID_CERT, state);
        return;
    }

    ETERM *file_arg = erl_element(2, args);
    char *file = erl_iolist_to_string(file_arg);

    zcert_save_public(cert, file);
    reply(client, ETERM_OK, state);

    erl_free(file);
}

static void handle_zcert_destroy(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 1);

    erl_czmq_state *state = ev_userdata(EV_A);
    zcert_t *cert = cert_from_arg(args, 1, state);
    if (!cert) {
        reply(client, ETERM_ERROR_INVALID_CERT, state);
        return;
    }

    zcert_destroy(&cert);
    clear_cert(int_arg(args, 1), state);

    reply(client, ETERM_OK, state);
}

static void erl_zpoller_start(EV_P_ erl_zpoller_t *poller) {
    ev_timer_again(EV_A_ &poller->watcher);
}

static void erl_zpoller_stop(EV_P_ erl_zpoller_t *poller) {
    ev_timer_stop(EV_A_ &poller->watcher);
}

static void poller_recv_cb(EV_P_ ev_timer *w, int revent) {
    erl_zpoller_t *poller = (erl_zpoller_t *)w;

    erl_czmq_state *state = ev_userdata(EV_A);
    void *socket = zpoller_wait(poller->zpoll, -1);
    if (socket) {
        zframe_t *frame = zframe_recv_nowait(socket);
        if (frame) {
            size_t frame_size = zframe_size(frame);
            byte *frame_data = zframe_data(frame);
            int more = zframe_more(frame);

            ETERM *result[2];
            ETERM *data_bin = erl_mk_binary((char*)frame_data, frame_size);
            result[0] = data_bin;
            result[1] = more ? ETERM_TRUE : ETERM_FALSE;

            ETERM *result_tuple = erl_mk_tuple(result, 2);
            reply(poller->id, result_tuple, state);

            zframe_destroy(&frame);
            erl_free_term(data_bin);
            erl_free_term(result_tuple);
        }
    }

    erl_zpoller_start(EV_A_ poller);
}

static erl_zpoller_t *erl_zpoller_new(void *socket) {
    assert(socket);

    erl_zpoller_t *poller = malloc(sizeof(*poller));
    assert(poller);

    poller->zpoll = zpoller_new(socket, NULL);
    assert(poller->zpoll);

    ev_init(&poller->watcher, poller_recv_cb);
    poller->watcher.repeat = .5;

    return poller;
}

static void erl_zpoller_destroy(erl_zpoller_t *poller) {
    zpoller_destroy(&poller->zpoll);
    erl_free_term(poller->id);
    free(poller);
}

static void handle_zpoller_new(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 1);
    erl_czmq_state *state = ev_userdata(EV_A);
    
    void *socket = socket_from_arg(args, 1, state);
    if (!socket) {
        reply(client, ETERM_ERROR_INVALID_SOCKET, state);
        return;
    }

    erl_zpoller_t *poller = erl_zpoller_new(socket);
    if (!poller) {
        reply(client, ETERM_ERROR, state);
        return;
    }

    char *poller_id = save_poller(poller, state);
    if (!poller_id) {
        erl_zpoller_destroy(poller);
        return;
    }
    
    poller->id = erl_mk_string(poller_id);
    erl_zpoller_start(EV_A_ poller);

    reply(client, poller->id, state);
}

static void handle_zpoller_destroy(EV_P_ ETERM *client, ETERM *args) {
    assert_tuple_size(args, 1);
    
    ETERM *poller_id_term = erl_element(1, args);
    char *poller_id = erl_iolist_to_string(poller_id_term);
    
    erl_czmq_state *state = ev_userdata(EV_A);
    erl_zpoller_t *poller = delete_poller(poller_id, state);
    if (!poller) {
        reply(client, ETERM_ERROR, state);
        erl_free(poller_id);
        return;
    }

    erl_zpoller_stop(EV_A_ poller);
    erl_zpoller_destroy(poller);

    reply(client, ETERM_OK, state);
    erl_free(poller_id);
}

#define CMD_TABLE \
CMD(CMD_PING,                   0, &handle_ping),                   \
CMD(CMD_ZSOCKET_NEW,            1, &handle_zsocket_new),            \
CMD(CMD_ZSOCKET_TYPE_STR,       2, &handle_zsocket_type_str),       \
CMD(CMD_ZSOCKET_BIND,           3, &handle_zsocket_bind),           \
CMD(CMD_ZSOCKET_CONNECT,        4, &handle_zsocket_connect),        \
CMD(CMD_ZSOCKET_SENDMEM,        5, &handle_zsocket_sendmem),        \
CMD(CMD_ZSOCKET_DESTROY,        6, &handle_zsocket_destroy),        \
CMD(CMD_ZSOCKOPT_GET_STR,       7, &handle_zsockopt_get_str),       \
CMD(CMD_ZSOCKOPT_GET_INT,       8, &handle_zsockopt_get_int),       \
CMD(CMD_ZSOCKOPT_SET_STR,       9, &handle_zsockopt_set_str),       \
CMD(CMD_ZSOCKOPT_SET_INT,       10, &handle_zsockopt_set_int),      \
CMD(CMD_ZSTR_SEND,              11, &handle_zstr_send),             \
CMD(CMD_ZSTR_RECV_NOWAIT,       12, &handle_zstr_recv_nowait),      \
CMD(CMD_ZFRAME_RECV_NOWAIT,     13, &handle_zframe_recv_nowait),    \
CMD(CMD_ZAUTH_NEW,              14, &handle_zauth_new),             \
CMD(CMD_ZAUTH_DENY,             15, &handle_zauth_deny),            \
CMD(CMD_ZAUTH_ALLOW,            16, &handle_zauth_allow),           \
CMD(CMD_ZAUTH_CONFIGURE_PLAIN,  17, &handle_zauth_configure_plain), \
CMD(CMD_ZAUTH_CONFIGURE_CURVE,  18, &handle_zauth_configure_curve), \
CMD(CMD_ZAUTH_DESTROY,          19, &handle_zauth_destroy),         \
CMD(CMD_ZCERT_NEW,              20, &handle_zcert_new),             \
CMD(CMD_ZCERT_APPLY,            21, &handle_zcert_apply),           \
CMD(CMD_ZCERT_PUBLIC_TXT,       22, &handle_zcert_public_txt),      \
CMD(CMD_ZCERT_SAVE_PUBLIC,      23, &handle_zcert_save_public),     \
CMD(CMD_ZCERT_DESTROY,          24, &handle_zcert_destroy),         \
CMD(CMD_ZSOCKET_UNBIND,         25, &handle_zsocket_unbind),        \
CMD(CMD_ZSOCKET_DISCONNECT,     26, &handle_zsocket_disconnect),    \
CMD(CMD_ZCTX_SET,               27, &handle_zctx_set_int),          \
CMD(CMD_ZSOCKET_POLLER_NEW,     28, &handle_zpoller_new),           \
CMD(CMD_ZSOCKET_POLLER_DESTROY, 29, &handle_zpoller_destroy)

#define CMD(type, index, handler) type=index
enum {
    CMD_TABLE,
    CMD_COUNT
};
#undef CMD

#define CMD(type, index, handler) [type]=handler
static cmd_handler handlers[] = {
    CMD_TABLE
};
#undef CMD

static void handle_cmd(EV_P_ byte *buf) {
    erl_czmq_state *state = ev_userdata(EV_A);

    ETERM *cmd_term = erl_decode(buf);
    if (!ERL_IS_TUPLE(cmd_term) || ERL_TUPLE_SIZE(cmd_term) != 3) {
        write_term(ETERM_ERROR_INVALID_CMD, state);
        return;
    }

    ETERM *id_term = erl_element(1, cmd_term);
    int id = ERL_INT_VALUE(id_term);

    if (id < 0 || id >= CMD_COUNT) {
        write_term(ETERM_ERROR_INVALID_CMD, state);
        erl_free_compound(cmd_term);
        return;
    }

    ETERM *client_term = erl_element(2, cmd_term);
    ETERM *args_term   = erl_element(3, cmd_term);

    cmd_handler cmd = handlers[id];
    cmd(EV_A_ client_term, args_term);

    erl_free_compound(cmd_term);
}

static void stdin_cb(EV_P_ ev_io *w, int revents) {
    byte cmd_buf[CMD_BUF_SIZE];
    int len = read_cmd(CMD_BUF_SIZE, cmd_buf);

    if (len == 0) {
        exit(EXIT_OK);
    } else if (len < 0) {
        exit(EXIT_PORT_READ_ERROR);
    } else {
        handle_cmd(EV_A_ cmd_buf);
    }
}

static void init_eterms() {
    ETERM_OK        = erl_mk_atom("ok");
    ETERM_UNDEFINED = erl_mk_atom("undefined");
    ETERM_TRUE      = erl_mk_atom("true");
    ETERM_FALSE     = erl_mk_atom("false");
    ETERM_PONG      = erl_mk_atom("pong");
    ETERM_ERROR     = erl_mk_atom("error");
    ETERM_ERROR_INVALID_SOCKET    = erl_format("{error,invalid_socket}");
    ETERM_ERROR_BIND_FAILED       = erl_format("{error,bind_failed}");
    ETERM_ERROR_UNBIND_FAILED     = erl_format("{error,unbind_failed}");
    ETERM_ERROR_CONNECT_FAILED    = erl_format("{error,connect_failed}");
    ETERM_ERROR_DISCONNECT_FAILED = erl_format("{error,disconnect_failed}");
    ETERM_ERROR_INVALID_AUTH      = erl_format("{error,invalid_auth}");
    ETERM_ERROR_INVALID_CERT      = erl_format("{error,invalid_cert}");
    ETERM_ERROR_INVALID_CMD       = erl_format("{error,invalid_command}");
}

void erl_czmq_init(erl_czmq_state *state) {
    erl_init(NULL, 0);

    init_eterms();

    state->ctx = zctx_new();
    assert(state->ctx);

    state->auth = NULL;
    state->pollers = zhash_new();
    vector_init(&state->sockets);
    vector_init(&state->certs);
}

int erl_czmq_run(erl_czmq_state *state) {
    assert(state);

    struct ev_loop *loop = ev_default_loop(0);
    ev_set_userdata(loop, state);

    ev_io *stdin_watcher = malloc(sizeof(*stdin_watcher));
    assert(stdin_watcher);

    ev_io_init(stdin_watcher, stdin_cb, STDIN_FILENO, EV_READ);
    ev_io_start(loop, stdin_watcher);
    ev_run(loop, 0);

    return 0;
}
