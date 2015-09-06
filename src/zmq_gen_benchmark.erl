%% ===================================================================
%% @author Garrett Smith <g@rre.tt>
%% @copyright 2014 Garrett Smith
%%
%% @doc Benchmarking behavior.
%%
%% @end
%% ===================================================================

-module(zmq_gen_benchmark).

-export([start_recv/1, start_recv/2, start_send/1, start_send/2, stop/1]).

-export([behaviour_info/1]).

behaviour_info(callbacks) ->
    [{init_recv, 1},
     {recv, 1},
     {init_send, 1},
     {send, 2},
     {terminate, 1}].

-define(DEFAULT_RECV_SOCKET_TYPE, pull).
-define(DEFAULT_SEND_TIME, 5).
-define(DEFAULT_MSG_SIZE, 512).

-record(state, {mod, mod_state, stop_time, msg, msg_count, last_log}).

%%%===================================================================
%%% API
%%%===================================================================

start_recv(Module) -> start_recv(Module, []).

start_recv(Module, Options) ->
    spawn(fun() -> recv(Module, Options) end).

start_send(Module) -> start_send(Module, []).

start_send(Module, Options) ->
    spawn(fun() -> send(Module, Options) end).

stop(Bench) ->
    erlang:send(Bench, stop),
    ok.

%%%===================================================================
%%% Recv
%%%===================================================================

recv(Mod, Options) ->
    recv_loop(init_recv_state(Mod, Options)).

init_recv_state(Mod, Options) ->
    handle_mod_init_recv(mod_init_recv(Mod, Options), Mod).

mod_init_recv(Mod, Options) -> Mod:init_recv(Options).

handle_mod_init_recv({ok, ModState}, Mod) ->
    #state{
       mod=Mod,
       mod_state=ModState,
       msg_count=0,
       last_log=0};
handle_mod_init_recv({error, Err}, _Mod) ->
    error({init_recv_error, Err}).

option(Name, Options, Default) ->
    proplists:get_value(Name, Options, Default).

now_millis() ->
    {M, S, U} = erlang:timestamp(),
    M * 1000000000 + S * 1000 + U div 1000.

recv_loop(State) ->
    recv_loop(recv_status(), State).

recv_status() ->
    receive
        stop -> stop
    after
        0 -> continue
    end.

recv_loop(continue, #state{mod=Mod, mod_state=ModState}=State) ->
    handle_recv(Mod:recv(ModState), maybe_log(State));
recv_loop(stop, State) ->
    terminate(State).

maybe_log(State) ->
    Now = now_millis(),
    maybe_log(time_to_log(Now, State), Now, State).

time_to_log(Now, #state{last_log=LastLog}) ->
    Now - LastLog >= 1000.

maybe_log(true, Now, #state{msg_count=MsgCount}=State) ->
    io:format("~p ~p~n", [Now, MsgCount]),
    reset_msg_count(State);
maybe_log(false, _Now, State) ->
    State.

reset_msg_count(State) ->
    State#state{msg_count=0, last_log=now_millis()}.

handle_recv({ok, _Msg, ModState}, State) ->
    recv_loop(set_mod_state(ModState, increment_msg_count(State)));
handle_recv({error, ModState}, State) ->
    recv_loop(set_mod_state(ModState, State)).

increment_msg_count(#state{msg_count=Count}=S) ->
    S#state{msg_count=Count + 1}.

set_mod_state(ModState, State) ->
    State#state{mod_state=ModState}.

%%%===================================================================
%%% Send
%%%===================================================================

send(Mod, Options) ->
    send_loop(init_send_state(Mod, Options)).

init_send_state(Mod, Options) ->
    handle_mod_init_send(mod_init_send(Mod, Options), Mod, Options).

mod_init_send(Mod, Options) -> Mod:init_send(Options).

handle_mod_init_send({ok, ModState}, Mod, Options) ->
    SendTime = option(time, Options, ?DEFAULT_SEND_TIME),
    StopTime = SendTime * 1000 + now_millis(),
    MsgSize = option(msg_size, Options, ?DEFAULT_MSG_SIZE),
    Msg = new_msg(MsgSize),
    #state{
       mod=Mod,
       mod_state=ModState,
       stop_time=StopTime,
       msg=Msg};
handle_mod_init_send({error, Err}, _Mod, _Options) ->
    error({init_send_error, Err}).

new_msg(Size) ->
    list_to_binary(lists:duplicate(Size, $!)).

send_loop(State) ->
    send_loop(send_status(State), State).

send_status(#state{stop_time=StopTime}) ->
    case now_millis() >= StopTime of
        true -> stop;
        false -> continue
    end.

send_loop(continue, #state{mod=Mod, mod_state=ModState, msg=Msg}=State) ->
    handle_send(Mod:send(Msg, ModState), State);
send_loop(stop, State) ->
    terminate(State).

handle_send({ok, ModState}, State) ->
    send_loop(set_mod_state(ModState, State));
handle_send({error, ModState}, State) ->
    send_loop(set_mod_state(ModState, State)).

%%%===================================================================
%%% Terminate
%%%===================================================================

terminate(#state{mod=Mod, mod_state=ModState}) ->
    Mod:terminate(ModState),
    exit(normal).
