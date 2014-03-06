%% ===================================================================
%% @author Garrett Smith <g@rre.tt>
%% @copyright 2014 Garrett Smith
%%
%% @doc Benchmarker for ezmq (pure Erlang ZeroMQ support).
%%
%% @end
%% ===================================================================

-module(ezmq_benchmark).

-behavior(zmq_gen_benchmark).

-export([start_recv/0, start_recv/1, start_send/0, start_send/1, stop/1]).

-export([init_recv/1, init_send/1, recv/1, send/2, terminate/1]).

-define(DEFAULT_PORT, 5555).
-define(DEFAULT_HOST, "localhost").
-define(DEFAULT_RECV_SOCKET_TYPE, router).
-define(DEFAULT_SEND_SOCKET_TYPE, dealer).
-define(RECV_TIMEOUT, 100).

-record(state, {socket}).

%%%===================================================================
%%% API
%%%===================================================================

start_recv() -> start_recv([]).

start_recv(Options) ->
    maybe_configure_code_path(Options),
    ensure_ezmq_started(),
    zmq_gen_benchmark:start_recv(?MODULE, Options).

maybe_configure_code_path(Options) ->
    handle_ezmq_home(proplists:get_value(ezmq_home, Options)).

handle_ezmq_home(undefined) -> ok;
handle_ezmq_home(Home) ->
    true = code:add_path(ebin_dir(Home)),
    true = code:add_path(ebin_dir(deps_dir(Home, "gen_listener_tcp"))).

ebin_dir(Home) ->
    filename:join(Home, "ebin").

deps_dir(Root, Dep) ->
    filename:join([Root, "deps", Dep]).

ensure_ezmq_started() ->
    application:start(sasl),
    application:start(gen_listener_tcp),
    application:start(ezmq).

start_send() -> start_send([]).

start_send(Options) ->
    maybe_configure_code_path(Options),
    ensure_ezmq_started(),
    zmq_gen_benchmark:start_send(?MODULE, Options).

stop(Benchmark) ->
    zmq_gen_benchmark:stop(Benchmark).

%%%===================================================================
%%% Recv
%%%===================================================================

init_recv(Options) ->
    SocketOpts = [{type, recv_socket_type(Options)}, {active, false}],
    {ok, Socket} = ezmq:socket(SocketOpts),
    ok = ezmq:bind(Socket, tcp, bind_port(Options), []),
    {ok, #state{socket=Socket}}.

recv_socket_type(Options) ->
    proplists:get_value(socket_type, Options, ?DEFAULT_RECV_SOCKET_TYPE).

bind_port(Options) ->
    proplists:get_value(port, Options, ?DEFAULT_PORT).

recv(#state{socket=Socket}=State) ->
    %% Would like to have a timeout, but something isn't working here.
    %% --> handle_erlzmq_recv(ezmq:recv(Socket, ?RECV_TIMEOUT), State).
    handle_erlzmq_recv(ezmq:recv(Socket), State).

handle_erlzmq_recv({ok, Msg}, State) ->
    {ok, Msg, State};
handle_erlzmq_recv({error, Err}, State) ->
    terminate(State),
    exit({recv_error, Err}).

%%%===================================================================
%%% Send
%%%===================================================================

init_send(Options) ->
    SocketOpts = [{type, send_socket_type(Options)}, {active, false}],
    {ok, Socket} = ezmq:socket(SocketOpts),
    ok = ezmq:connect(
           Socket, tcp, connect_host(Options), connect_port(Options), []),
    {ok, #state{socket=Socket}}.

send_socket_type(Options) ->
    proplists:get_value(socket_type, Options, ?DEFAULT_SEND_SOCKET_TYPE).

connect_host(Options) ->
    proplists:get_value(host, Options, ?DEFAULT_HOST).

connect_port(Options) ->
    proplists:get_value(port, Options, ?DEFAULT_PORT).

send(Msg, #state{socket=Socket}=State) ->
    handle_ezmq_send(ezmq:send(Socket, [Msg]), State).

handle_ezmq_send(ok, State) -> {ok, State}.

%%%===================================================================
%%% Terminate
%%%===================================================================

terminate(#state{socket=Socket}) ->
    ok = ezmq:close(Socket).
