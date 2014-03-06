%% ===================================================================
%% @author Garrett Smith <g@rre.tt>
%% @copyright 2014 Garrett Smith
%%
%% @doc Benchmarker for czmq (external port bindings).
%%
%% @end
%% ===================================================================

-module(czmq_benchmark).

-behavior(zmq_gen_benchmark).

-export([start_recv/0, start_recv/1, start_send/0, start_send/1, stop/1]).

-export([init_recv/1, init_send/1, recv/1, send/2, terminate/1]).

-include("czmq.hrl").

-define(DEFAULT_PORT, 5555).
-define(DEFAULT_HOST, "localhost").
-define(DEFAULT_RECV_SOCKET_TYPE, ?ZMQ_PULL).
-define(DEFAULT_SEND_SOCKET_TYPE, ?ZMQ_PUSH).
-define(DEFAULT_POLL_INTERVAL, 100).

-record(state, {ctx, socket, poll_interval}).

%%%===================================================================
%%% API
%%%===================================================================

start_recv() -> start_recv([]).

start_recv(Options) ->
    zmq_gen_benchmark:start_recv(?MODULE, Options).

start_send() -> start_send([]).

start_send(Options) ->
    zmq_gen_benchmark:start_send(?MODULE, Options).

stop(Benchmark) ->
    zmq_gen_benchmark:stop(Benchmark).

%%%===================================================================
%%% Recv
%%%===================================================================

init_recv(Options) ->
    PollInterval = poll_interval_option(Options),
    {ok, Ctx} = czmq:start_link(),
    Socket = czmq:zsocket_new(Ctx, recv_socket_type(Options)),
    czmq:zsocket_bind(Socket, bind_endpoint(Options)),
    {ok, #state{ctx=Ctx, socket=Socket, poll_interval=PollInterval}}.

poll_interval_option(Options) ->
    proplists:get_value(poll_interval, Options, ?DEFAULT_POLL_INTERVAL).

recv_socket_type(Options) ->
    proplists:get_value(socket_type, Options, ?DEFAULT_RECV_SOCKET_TYPE).

bind_endpoint(Options) ->
    Port = proplists:get_value(port, Options, ?DEFAULT_PORT),
    "tcp://*:" ++ integer_to_list(Port).

recv(#state{socket=Socket}=State) ->
    handle_czmq_recv(czmq:zstr_recv_nowait(Socket), State).

handle_czmq_recv({ok, Msg}, State) ->
    {ok, Msg, State};
handle_czmq_recv(error, State) ->
    sleep_poll_interval(State),
    {error, State}.

sleep_poll_interval(#state{poll_interval=I}) ->
    timer:sleep(I).

%%%===================================================================
%%% Send
%%%===================================================================

init_send(Options) ->
    {ok, Ctx} = czmq:start_link(),
    Socket = czmq:zsocket_new(Ctx, send_socket_type(Options)),
    ok = czmq:zsocket_connect(Socket, connect_endpoint(Options)),
    {ok, #state{ctx=Ctx, socket=Socket}}.

send_socket_type(Options) ->
    proplists:get_value(socket_type, Options, ?DEFAULT_SEND_SOCKET_TYPE).

connect_endpoint(Options) ->
    Port = proplists:get_value(port, Options, ?DEFAULT_PORT),
    Host = proplists:get_value(host, Options, ?DEFAULT_HOST),
    "tcp://" ++ Host ++ ":" ++ integer_to_list(Port).

send(Msg, #state{socket=Socket}=State) ->
    handle_czmq_send(czmq:zstr_send(Socket, Msg), State).

handle_czmq_send(ok, State) -> {ok, State};
handle_czmq_send(error, State) -> {error, State}.

%%%===================================================================
%%% Terminate
%%%===================================================================

terminate(#state{ctx=Ctx}) ->
    czmq:terminate(Ctx).
