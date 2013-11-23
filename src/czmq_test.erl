-module(czmq_test).

-export([test/0,
         zstr_send_recv/1,
         sendmem_framerecv/1]).

-include("czmq.hrl").

test() ->
    {ok, C} = czmq:start_link(),
    zstr_send_recv(C),
    sendmem_framerecv(C),
    czmq:terminate(C).

%%--------------------------------------------------------------------
%% @doc Tests basic zstr send and receive.
%% @end
%%--------------------------------------------------------------------

zstr_send_recv(C) ->
    Writer = czmq:zsocket_new(C, ?ZMQ_PUSH),
    {ok, Port} = czmq:zsocket_bind(C, Writer, "tcp://*:*"),

    Reader = czmq:zsocket_new(C, ?ZMQ_PULL),
    ok = czmq:zsocket_connect(C, Reader, connect_endpoint(Port)),

    Msg = "Watson, put on your shirt",
    ok = czmq:zstr_send(C, Writer, Msg),

    timer:sleep(100),

    {ok, Msg} = czmq:zstr_recv_nowait(C, Reader),

    czmq:zsocket_destroy(C, Writer),
    czmq:zsocket_destroy(C, Reader).

%%--------------------------------------------------------------------
%% @doc Tests sendmem and frame receieves as per
%% http://czmq.zeromq.org/manual:zsocket.
%% @end
%%--------------------------------------------------------------------

sendmem_framerecv(C) ->
    Writer = czmq:zsocket_new(C, ?ZMQ_PUSH),
    Reader = czmq:zsocket_new(C, ?ZMQ_PULL),

    "PUSH" = czmq:zsocket_type_str(C, Writer),
    "PULL" = czmq:zsocket_type_str(C, Reader).

%%     int rc = zsocket_bind (writer, "tcp://%s:%d", interf, service);
%%     assert (rc == service);

%% #if (ZMQ_VERSION >= ZMQ_MAKE_VERSION (3,2,0))
%%     //  Check unbind
%%     rc = zsocket_unbind (writer, "tcp://%s:%d", interf, service);
%%     assert (rc == 0);

%%     //  In some cases and especially when running under Valgrind, doing
%%     //  a bind immediately after an unbind causes an EADDRINUSE error.
%%     //  Even a short sleep allows the OS to release the port for reuse.
%%     zclock_sleep (100);

%%     //  Bind again
%%     rc = zsocket_bind (writer, "tcp://%s:%d", interf, service);
%%     assert (rc == service);
%% #endif

%%     rc = zsocket_connect (reader, "tcp://%s:%d", domain, service);
%%     assert (rc == 0);
%%     zstr_send (writer, "HELLO");
%%     char *message = zstr_recv (reader);
%%     assert (message);
%%     assert (streq (message, "HELLO"));
%%     free (message);

%%     //  Test binding to ports
%%     int port = zsocket_bind (writer, "tcp://%s:*", interf);
%%     assert (port >= ZSOCKET_DYNFROM && port <= ZSOCKET_DYNTO);

%%     assert (zsocket_poll (writer, 100) == false);

%%     rc = zsocket_connect (reader, "txp://%s:%d", domain, service);
%%     assert (rc == -1);

%%     //  Test sending frames to socket
%%     rc = zsocket_sendmem (writer,"ABC", 3, ZFRAME_MORE);
%%     assert (rc == 0);
%%     rc = zsocket_sendmem (writer, "DEFG", 4, 0);
%%     assert (rc == 0);

%%     zframe_t *frame = zframe_recv (reader);
%%     assert (frame);
%%     assert (zframe_streq (frame, "ABC"));
%%     assert (zframe_more (frame));
%%     zframe_destroy (&frame);

%%     frame = zframe_recv (reader);
%%     assert (frame);
%%     assert (zframe_streq (frame, "DEFG"));
%%     assert (!zframe_more (frame));
%%     zframe_destroy (&frame);

%%     zsocket_destroy (ctx, writer); 

connect_endpoint(Port) ->
    "tcp://localhost:" ++ integer_to_list(Port).
