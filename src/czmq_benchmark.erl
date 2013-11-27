-module(czmq_benchmark).

-export([start_recv/0, start_recv/1, stop/1, recv/0, recv/1]).

-include("czmq.hrl").

-define(DEFAULT_PORT, 5555).
-define(DEFAULT_RECV_SOCKET_TYPE, ?ZMQ_PULL).
-define(DEFAULT_POLL_INTERVAL, 100).

-record(options, {port, socket_type, poll_interval}).

start_recv() -> start_recv([]).

start_recv(Options) ->
    spawn(fun() -> recv(Options) end).

stop(P) ->
    exit(P, shutdown),
    ok.

recv() -> recv([]).

recv(Options) ->
    #options{
       port=Port,
       socket_type=SocketType,
       poll_interval=PollInterval} = parse_options(Options),
    {ok, Ctx} = czmq:start_link(),
    Socket = czmq:zsocket_new(Ctx, SocketType),
    czmq:zsocket_bind(Socket, bind_endpoint(Port)),
    recv_loop(Socket, 0, now_millis(), PollInterval),
    exit(Ctx).

parse_options(Opts) ->
    Val = fun(Name, Default) -> proplists:get_value(Name, Opts, Default) end,
    #options{
       port=Val(port, ?DEFAULT_PORT),
       socket_type=Val(socket_type, ?DEFAULT_RECV_SOCKET_TYPE),
       poll_interval=Val(poll_interval, ?DEFAULT_POLL_INTERVAL)}.

bind_endpoint(Port) ->
    "tcp://*:" ++ integer_to_list(Port).

now_millis() ->
    {M, S, U} = erlang:now(),
    M * 1000000000 + S * 1000 + U div 1000.

recv_loop(Socket, MsgCount0, LastLog0, PollInterval) ->
    {MsgCount, LastLog} = maybe_log(MsgCount0, LastLog0),
    handle_recv(
      czmq:zstr_recv_nowait(Socket),
      Socket, MsgCount, LastLog, PollInterval).

maybe_log(MsgCount, LastLog) ->
    Now = now_millis(),
    maybe_log(time_to_log(Now, LastLog), Now, MsgCount, LastLog).

time_to_log(Now, LastLog) -> Now - LastLog >= 1000.

maybe_log(true, Now, MsgCount, _LastLog) ->
    io:format("~p ~p~n", [Now, MsgCount]),
    {0, Now};
maybe_log(false, _Now, MsgCount, LastLog) ->
    {MsgCount, LastLog}.            

handle_recv(error, Socket, MsgCount, LastLog, PollInterval) ->
    timer:sleep(PollInterval),
    recv_loop(Socket, MsgCount, LastLog, PollInterval);
handle_recv({ok, _Msg}, Socket, MsgCount, LastLog, PollInterval) ->
    recv_loop(Socket, MsgCount + 1, LastLog, PollInterval).
