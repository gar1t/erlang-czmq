#ifndef __ERL_CZMQ_H_INCLUDED__
#define __ERL_CZMQ_H_INCLUDED__

#include "czmq.h"
#include "vector.h"

#define ERL_CZMQ_REPLY_BUF_SIZE 10240

typedef struct {
    byte reply_buf[ERL_CZMQ_REPLY_BUF_SIZE];
    zctx_t *ctx;
    vector sockets;
} erl_czmq_state;

void erl_czmq_init(erl_czmq_state *state);

int erl_czmq_loop(erl_czmq_state *state);

#endif
