-module(erlzmq_benchmark).

-behavior(zmq_gen_benchmark).

-export([start_recv/0, start_recv/1, stop/1]).

-export([init_recv/1, recv_nowait/1, terminate/1]).

-define(DEFAULT_PORT, 5555).
-define(DEFAULT_RECV_SOCKET_TYPE, pull).

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

stop(Benchmark) ->
    zmq_gen_benchmark:stop(Benchmark).

%%%===================================================================
%%% Callbacks
%%%===================================================================

init_recv(Options) ->
    {ok, Ctx} = erlzmq:context(),
    {ok, Socket} = erlzmq:socket(Ctx, recv_socket_type(Options)),
    ok = erlzmq:bind(Socket, bind_endpoint(Options)),
    {ok, #state{ctx=Ctx, socket=Socket}}.

recv_socket_type(Options) ->
    proplists:get_value(socket_type, Options, ?DEFAULT_RECV_SOCKET_TYPE).

bind_endpoint(Options) ->
    Port = proplists:get_value(port, Options, ?DEFAULT_PORT),
    "tcp://*:" ++ integer_to_list(Port).

recv_nowait(#state{socket=Socket}=State) ->
    handle_erlzmq_recv(erlzmq:recv(Socket, [dontwait]), State).

handle_erlzmq_recv({ok, Msg}, State) -> {ok, Msg, State};
handle_erlzmq_recv({error, eagain}, State) -> {error, State};
handle_erlzmq_recv({error, Err}, State) ->
    terminate(State),
    exit({recv_error, Err}).

terminate(#state{socket=Socket, ctx=Ctx}) ->
    ok = erlzmq:close(Socket, 1000),
    ok = erlzmq:term(Ctx, 1000).
