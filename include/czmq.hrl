-define(ZMQ_PAIR, 0).
-define(ZMQ_PUB, 1).
-define(ZMQ_SUB, 2).
-define(ZMQ_REQ, 3).
-define(ZMQ_REP, 4).
-define(ZMQ_DEALER, 5).
-define(ZMQ_ROUTER, 6).
-define(ZMQ_PULL, 7).
-define(ZMQ_PUSH, 8).
-define(ZMQ_XPUB, 9).
-define(ZMQ_XSUB, 10).
-define(ZMQ_STREAM, 11).

-define(ZFRAME_MORE, 1).
-define(ZFRAME_REUSE, 2).
-define(ZFRAME_DONTWAIT, 4).

-define(CURVE_ALLOW_ANY, "*").

%% These *must* correspond to the handlers in czmq_port.c
-define(CMD_PING,                    0).
-define(CMD_ZSOCKET_NEW,             1).
-define(CMD_ZSOCKET_TYPE_STR,        2).
-define(CMD_ZSOCKET_BIND,            3).
-define(CMD_ZSOCKET_CONNECT,         4).
-define(CMD_ZSOCKET_SENDMEM,         5).
-define(CMD_ZSOCKET_DESTROY,         6).
-define(CMD_ZSOCKOPT_GET_STR,        7).
-define(CMD_ZSOCKOPT_GET_INT,        8).
-define(CMD_ZSOCKOPT_SET_STR,        9).
-define(CMD_ZSOCKOPT_SET_INT,       10).
-define(CMD_ZSTR_SEND,              11).
-define(CMD_ZSTR_RECV_NOWAIT,       12).
-define(CMD_ZFRAME_RECV_NOWAIT,     13).
-define(CMD_ZAUTH_NEW,              14).
-define(CMD_ZAUTH_DENY,             15).
-define(CMD_ZAUTH_ALLOW,            16).
-define(CMD_ZAUTH_CONFIGURE_PLAIN,  17).
-define(CMD_ZAUTH_CONFIGURE_CURVE,  18).
-define(CMD_ZAUTH_DESTROY,          19).
-define(CMD_ZCERT_NEW,              20).
-define(CMD_ZCERT_APPLY,            21).
-define(CMD_ZCERT_PUBLIC_TXT,       22).
-define(CMD_ZCERT_SAVE_PUBLIC,      23).
-define(CMD_ZCERT_DESTROY,          24).
-define(CMD_ZSOCKET_UNBIND,         25).
-define(CMD_ZSOCKET_DISCONNECT,     26).
-define(CMD_ZCTX_SET,               27).
-define(CMD_ZPOLLER_NEW,            28).
-define(CMD_ZPOLLER_DESTROY,        29).


%% These *must* correspond to the ZCTX_SET_XXX definitions in czmq_port.c
-define(ZCTX_SET_IOTHREADS, 0).
-define(ZCTX_SET_LINGER, 1).
-define(ZCTX_SET_PIPEHWM, 2).
-define(ZCTX_SET_SNDHWM, 3).
-define(ZCTX_SET_RCVHWM, 4).

%% These *must* correspond to the ZSOCKOPT_XXX definitions in czmq_port.c
-define(ZSOCKOPT_ZAP_DOMAIN, 0).
-define(ZSOCKOPT_PLAIN_SERVER, 1).
-define(ZSOCKOPT_PLAIN_USERNAME, 2).
-define(ZSOCKOPT_PLAIN_PASSWORD, 3).
-define(ZSOCKOPT_CURVE_SERVER, 4).
-define(ZSOCKOPT_CURVE_SERVERKEY, 5).
-define(ZSOCKOPT_BACKLOG, 6).
-define(ZSOCKOPT_SNDHWM, 7).
-define(ZSOCKOPT_RCVHWM, 8).
-define(ZSOCKOPT_SUBSCRIBE, 9).
-define(ZSOCKOPT_UNSUBSCRIBE, 10).
-define(ZSOCKOPT_IDENTITY, 11).
-define(ZPOLLER_ACTIVE, active).
