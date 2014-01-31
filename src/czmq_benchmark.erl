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

-export([start_recv/0, start_recv/1, stop/1]).

-export([init_recv/1, recv_nowait/1, terminate/1]).

-include("czmq.hrl").

-define(DEFAULT_PORT, 5555).
-define(DEFAULT_RECV_SOCKET_TYPE, ?ZMQ_PULL).

-record(state, {ctx, socket}).

%%%===================================================================
%%% API
%%%===================================================================

start_recv() -> start_recv([]).

start_recv(Options) ->
    zmq_gen_benchmark:start_recv(?MODULE, Options).

stop(Benchmark) ->
    zmq_gen_benchmark:stop(Benchmark).

%%%===================================================================
%%% Callbacks
%%%===================================================================

init_recv(Options) ->
    {ok, Ctx} = czmq:start_link(),
    Socket = czmq:zsocket_new(Ctx, recv_socket_type(Options)),
    czmq:zsocket_bind(Socket, bind_endpoint(Options)),
    {ok, #state{ctx=Ctx, socket=Socket}}.

recv_socket_type(Options) ->
    proplists:get_value(socket_type, Options, ?DEFAULT_RECV_SOCKET_TYPE).

bind_endpoint(Options) ->
    Port = proplists:get_value(port, Options, ?DEFAULT_PORT),
    "tcp://*:" ++ integer_to_list(Port).

recv_nowait(#state{socket=Socket}=State) ->
    handle_czmq_recv(czmq:zstr_recv_nowait(Socket), State).

handle_czmq_recv({ok, Msg}, State) -> {ok, Msg, State};
handle_czmq_recv(error, State) -> {error, State}.

terminate(#state{ctx=Ctx}) ->
    czmq:terminate(Ctx).
