-module(czmq_test).

-export([test/0,
         zstr_send_recv/1,
         sendmem_framerecv/1]).

-include("czmq.hrl").

test() ->
    {ok, Ctx} = czmq:start_link(),
    zstr_send_recv(Ctx),
    sendmem_framerecv(Ctx),
    czmq:terminate(Ctx).

%%--------------------------------------------------------------------
%% @doc Tests basic zstr send and receive.
%% @end
%%--------------------------------------------------------------------

zstr_send_recv(Ctx) ->
    Writer = czmq:zsocket_new(Ctx, ?ZMQ_PUSH),
    {ok, Port} = czmq:zsocket_bind(Writer, "tcp://*:*"),

    Reader = czmq:zsocket_new(Ctx, ?ZMQ_PULL),
    ok = czmq:zsocket_connect(Reader, connect_endpoint(Port)),

    Msg = "Watson, put on your shirt",
    ok = czmq:zstr_send(Writer, Msg),

    timer:sleep(100),

    {ok, Msg} = czmq:zstr_recv_nowait(Reader),

    error = czmq:zstr_recv_nowait(Reader),

    czmq:zsocket_destroy(Writer),
    czmq:zsocket_destroy(Reader).

%%--------------------------------------------------------------------
%% @doc Tests sendmem and frame receieves as per
%% http://czmq.zeromq.org/manual:zsocket.
%% @end
%%--------------------------------------------------------------------

sendmem_framerecv(Ctx) ->
    Writer = czmq:zsocket_new(Ctx, ?ZMQ_PUSH),
    "PUSH" = czmq:zsocket_type_str(Writer),
    {ok, Port} = czmq:zsocket_bind(Writer, "tcp://*:*"),

    Reader = czmq:zsocket_new(Ctx, ?ZMQ_PULL),
    "PULL" = czmq:zsocket_type_str(Reader),
    ok = czmq:zsocket_connect(Reader, connect_endpoint(Port)),

    ok = czmq:zsocket_sendmem(Writer, "ABC", ?ZFRAME_MORE),
    ok = czmq:zsocket_sendmem(Writer, "DEFG"),

    timer:sleep(100),

    {ok, Frame1} = czmq:zframe_recv_nowait(Reader),

    <<"ABC">> = czmq:zframe_data(Frame1),
    true = czmq:zframe_more(Frame1),

    {ok, Frame2} = czmq:zframe_recv_nowait(Reader),
    <<"DEFG">> = czmq:zframe_data(Frame2),
    false = czmq:zframe_more(Frame2),

    error = czmq:zframe_recv_nowait(Reader),

    czmq:zsocket_destroy(Writer),
    czmq:zsocket_destroy(Reader).

connect_endpoint(Port) ->
    "tcp://localhost:" ++ integer_to_list(Port).
