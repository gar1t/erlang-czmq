%% ===================================================================
%% @author Garrett Smith <g@rre.tt>
%% @copyright 2014 Garrett Smith
%%
%% @doc Benchmarker for erlzmq (NIF bindings).
%%
%% @end
%% ===================================================================

-module(erlzmq_benchmark).

-behavior(zmq_gen_benchmark).

-export([start_recv/0, start_recv/1, start_send/0, start_send/1, stop/1]).

-export([init_recv/1, init_send/1, recv/1, send/2, terminate/1]).

-define(DEFAULT_PORT, 5555).
-define(DEFAULT_HOST, "localhost").
-define(DEFAULT_RECV_SOCKET_TYPE, pull).
-define(DEFAULT_SEND_SOCKET_TYPE, push).
-define(RECV_TIMEOUT, 100).

-record(state, {ctx, socket}).

%%%===================================================================
%%% API
%%%===================================================================

start_recv() -> start_recv([]).

start_recv(Options) ->
    maybe_configure_code_path(Options),
    zmq_gen_benchmark:start_recv(?MODULE, Options).

maybe_configure_code_path(Options) ->
    handle_erlzmq_home(proplists:get_value(erlzmq_home, Options)).

handle_erlzmq_home(undefined) -> ok;
handle_erlzmq_home(Home) ->
    true = code:add_path(ebin_dir(Home)).

ebin_dir(Home) ->
    filename:join(Home, "ebin").

start_send() -> start_send([]).

start_send(Options) ->
    maybe_configure_code_path(Options),
    zmq_gen_benchmark:start_send(?MODULE, Options).

stop(Benchmark) ->
    zmq_gen_benchmark:stop(Benchmark).

%%%===================================================================
%%% Recv
%%%===================================================================

init_recv(Options) ->
    {ok, Ctx} = erlzmq:context(),
    {ok, Socket} = erlzmq:socket(Ctx, recv_socket_type(Options)),
    ok = erlzmq:setsockopt(Socket, rcvtimeo, ?RECV_TIMEOUT),
    ok = erlzmq:bind(Socket, bind_endpoint(Options)),
    {ok, #state{ctx=Ctx, socket=Socket}}.

recv_socket_type(Options) ->
    proplists:get_value(socket_type, Options, ?DEFAULT_RECV_SOCKET_TYPE).

bind_endpoint(Options) ->
    Port = proplists:get_value(port, Options, ?DEFAULT_PORT),
    "tcp://*:" ++ integer_to_list(Port).

recv(#state{socket=Socket}=State) ->
    handle_erlzmq_recv(erlzmq:recv(Socket), State).

handle_erlzmq_recv({ok, Msg}, State) -> {ok, Msg, State};
handle_erlzmq_recv({error, eagain}, State) -> {error, State};
handle_erlzmq_recv({error, Err}, State) ->
    terminate(State),
    exit({recv_error, Err}).

%%%===================================================================
%%% Send
%%%===================================================================

init_send(Options) ->
    {ok, Ctx} = erlzmq:context(),
    {ok, Socket} = erlzmq:socket(Ctx, send_socket_type(Options)),
    ok = erlzmq:connect(Socket, connect_endpoint(Options)),
    {ok, #state{ctx=Ctx, socket=Socket}}.

send_socket_type(Options) ->
    proplists:get_value(socket_type, Options, ?DEFAULT_SEND_SOCKET_TYPE).

connect_endpoint(Options) ->
    Port = proplists:get_value(port, Options, ?DEFAULT_PORT),
    Host = proplists:get_value(host, Options, ?DEFAULT_HOST),
    "tcp://" ++ Host ++ ":" ++ integer_to_list(Port).

send(Msg, #state{socket=Socket}=State) ->
    handle_erlzmq_send(erlzmq:send(Socket, Msg), State).

handle_erlzmq_send(ok, State) -> {ok, State}.

%%%===================================================================
%%% Terminate
%%%===================================================================

terminate(#state{socket=Socket, ctx=Ctx}) ->
    ok = erlzmq:close(Socket, 1000),
    ok = erlzmq:term(Ctx, 1000).
