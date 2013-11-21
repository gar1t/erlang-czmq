-module(czmq_test).

-export([basic_send_recv/0]).

-include("czmq.hrl").

basic_send_recv() ->
    {ok, C} = czmq:start_link(),

    Writer = czmq:zsocket_new(C, ?ZMQ_PUSH),
    {ok, Port} = czmq:zsocket_bind(C, Writer, "tcp://*:*"),

    Reader = czmq:zsocket_new(C, ?ZMQ_PULL),
    ok = czmq:zsocket_connect(C, Reader, connect_endpoint(Port)),

    Msg = "Watson, put on your shirt",
    ok = czmq:zstr_send(C, Writer, Msg),

    timer:sleep(100),

    {ok, Msg} = czmq:zstr_recv_nowait(C, Reader),

    czmq:terminate(C).


connect_endpoint(Port) ->
    "tcp://localhost:" ++ integer_to_list(Port).
