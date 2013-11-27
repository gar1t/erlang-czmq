-module(czmq).

-behavior(gen_server).

-export([start/0, start_link/0,
         ping/1, ping/2,
         zsocket_new/2,
         zsocket_type_str/1,
         zsocket_bind/2,
         zsocket_connect/2,
         zsocket_sendmem/2,
         zsocket_sendmem/3,
         zsocket_destroy/1,
         zstr_send/2,
         zstr_recv_nowait/1,
         zframe_recv_nowait/1,
         zframe_data/1,
         zframe_more/1,
         terminate/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("czmq.hrl").

-record(state, {port}).

-define(DEFAULT_PING_TIMEOUT, 1000).
-define(MSG_TIMEOUT, 1000).

%% These *must* correspond to the handlers in czmq_port.c
-define(CMD_PING,                0).
-define(CMD_ZSOCKET_NEW,         1).
-define(CMD_ZSOCKET_TYPE_STR,    2).
-define(CMD_ZSOCKET_BIND,        3).
-define(CMD_ZSOCKET_CONNECT,     4).
-define(CMD_ZSOCKET_SENDMEM,     5).
-define(CMD_ZSOCKET_DESTROY,     6).
-define(CMD_ZSTR_SEND,           7).
-define(CMD_ZSTR_RECV_NOWAIT,    8).
-define(CMD_ZFRAME_RECV_NOWAIT,  9).

%%%===================================================================
%%% Start / init
%%%===================================================================

start() ->
    gen_server:start(?MODULE, [], []).

start_link() ->
    gen_server:start_link(?MODULE, [], []).

init([]) ->
    process_flag(trap_exit, true),
    Port = start_port(),
    {ok, #state{port=Port}}.

start_port() ->
    open_port({spawn, port_exe()}, [{packet, 2}, binary, exit_status]).

port_exe() ->
    EbinDir = filename:dirname(code:which(?MODULE)),
    filename:join([EbinDir, "..", "priv", "czmq-port"]).

%%%===================================================================
%%% API
%%%===================================================================

ping(Ctx) ->
    ping(Ctx, ?DEFAULT_PING_TIMEOUT).

ping(Ctx, Timeout) ->
    gen_server:call(Ctx, {?CMD_PING, {}}, Timeout).

zsocket_new(Ctx, Type) ->
    Socket = gen_server:call(Ctx, {?CMD_ZSOCKET_NEW, {Type}}, infinity),
    bind_socket(Socket, Ctx).

bind_socket(Socket, Ctx) -> {Ctx, Socket}.

zsocket_type_str({Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZSOCKET_TYPE_STR, {Socket}}, infinity).

zsocket_bind({Ctx, Socket}, Endpoint) ->
    gen_server:call(Ctx, {?CMD_ZSOCKET_BIND, {Socket, Endpoint}}, infinity).

zsocket_connect({Ctx, Socket}, Endpoint) ->
    gen_server:call(Ctx, {?CMD_ZSOCKET_CONNECT, {Socket, Endpoint}}, infinity).

zsocket_sendmem(BoundSocket, Data) ->
    zsocket_sendmem(BoundSocket, Data, 0).

zsocket_sendmem({Ctx, Socket}, Data, Flags) ->
    DataBin = iolist_to_binary(Data),
    gen_server:call(
      Ctx, {?CMD_ZSOCKET_SENDMEM, {Socket, DataBin, Flags}}, infinity).

zsocket_destroy({Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZSOCKET_DESTROY, {Socket}}, infinity).

zstr_send({Ctx, Socket}, Data) ->
    gen_server:call(Ctx, {?CMD_ZSTR_SEND, {Socket, Data}}, infinity).

zstr_recv_nowait({Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZSTR_RECV_NOWAIT, {Socket}}, infinity).

zframe_recv_nowait({Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZFRAME_RECV_NOWAIT, {Socket}}, infinity).

zframe_data({Data, _More}) -> Data.

zframe_more({_Data, More}) -> More.

terminate(Ctx) ->
    gen_server:call(Ctx, terminate, infinity).

%%%===================================================================
%%% Callbacks
%%%===================================================================

handle_call(terminate, _From, State) ->
    {stop, normal, ok, State};
handle_call(Msg, _From, State) ->
    Reply = send_to_port(Msg, State),
    NextState = handle_msg_reply(Msg, Reply, State),
    {reply, Reply, NextState}.

send_to_port(Msg, #state{port=Port}) ->
    erlang:send(Port, {self(), {command, term_to_binary(Msg)}}),
    receive
        {Port, {data, Data}} ->
            binary_to_term(Data);
        {Port, {exit_status, Status}} ->
            exit({port_exit, Status});
        {'EXIT', Port, Reason} ->
            exit({port_exit, Reason})
    end.

handle_msg_reply(_Msg, _Reply, State) ->
    %% TODO: For creating sockets, we'll need to maintain an association
    %% between the socket ID and the process that should receive messages from
    %% that socket.
    State.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({Port, {exit_status, Exit}}, #state{port=Port}=State) ->
    {stop, {port_process_exit, Exit}, State};
handle_info({'EXIT', Port, Reason}, #state{port=Port}=State) ->
    {stop, {port_exit, Reason}, State};
handle_info(Msg, State) ->
    {stop, {unhandled_msg, Msg}, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
