-module(czmq).

-behavior(gen_server).

-export([start/0, start_link/0,
         ping/1, ping/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {port}).

-define(DEFAULT_PING_TIMEOUT, 1000).
-define(MSG_TIMEOUT, 1000).

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
    {ok, #state{port=Port}, 0}.

start_port() ->
    open_port({spawn, port_exe()}, [{packet, 2}, binary, exit_status]).

port_exe() ->
    EbinDir = filename:dirname(code:which(?MODULE)),
    filename:join([EbinDir, "..", "priv", "czmq_port"]).

%%%===================================================================
%%% API
%%%===================================================================

ping(C) ->
    ping(C, ?DEFAULT_PING_TIMEOUT).

ping(C, Timeout) ->
    gen_server:call(C, ping, Timeout).

%%%===================================================================
%%% Callbacks
%%%===================================================================

handle_call(Msg, _From, State) ->
    Reply = send_to_port(Msg, State),
    NextState = handle_msg_reply(Msg, Reply, State),
    {reply, Reply, NextState, 0}.

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

handle_info(timeout, State) ->
    Reply = send_to_port(poll, State),
    NextState = handle_poll_reply(Reply, State),
    {noreply, NextState, ?MSG_TIMEOUT};
handle_info({Port, {exit_status, Exit}}, #state{port=Port}=State) ->
    {stop, {port_process_exit, Exit}, State};
handle_info({'EXIT', Port, Reason}, #state{port=Port}=State) ->
    {stop, {port_exit, Reason}, State};
handle_info(Msg, State) ->
    {stop, {unhandled_msg, Msg}, State}.

handle_poll_reply(Reply, State) ->
    io:format("*** poll reply was ~p~n", [Reply]),
    State.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
