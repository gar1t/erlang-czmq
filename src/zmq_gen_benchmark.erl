-module(zmq_gen_benchmark).

-export([start_recv/1, start_recv/2, stop/1]).

-export([behaviour_info/1]).

behaviour_info(callbacks) ->
    [{init_recv, 1},
     {recv_nowait, 1},
     {terminate, 1}].

-define(DEFAULT_RECV_SOCKET_TYPE, pull).
-define(DEFAULT_POLL_INTERVAL, 100).

-record(state, {mod, mod_state, poll_interval, msg_count, last_log}).

start_recv(Module) -> start_recv(Module, []).

start_recv(Module, Options) ->
    spawn(fun() -> recv(Module, Options) end).

stop(Bench) ->
    erlang:send(Bench, stop),
    ok.

recv(Mod, Options) ->
    recv_loop(init_recv_state(Mod, Options)).

init_recv_state(Mod, Options) ->
    handle_mod_init_recv(mod_init_recv(Mod, Options), Mod, Options).

mod_init_recv(Mod, Options) -> Mod:init_recv(Options).

handle_mod_init_recv({ok, ModState}, Mod, Options) ->
    PollInterval = option(poll_interval, Options, ?DEFAULT_POLL_INTERVAL),
    #state{
       mod=Mod,
       mod_state=ModState,
       poll_interval=PollInterval,
       msg_count=0,
       last_log=0};
handle_mod_init_recv({error, Err}, _Mod, _Options) ->
    exit({init_error, Err}).

option(Name, Options, Default) ->
    proplists:get_value(Name, Options, Default).

now_millis() ->
    {M, S, U} = erlang:now(),
    M * 1000000000 + S * 1000 + U div 1000.

recv_loop(State) ->
    recv_loop(run_status(), State).

run_status() ->
    receive
        stop -> stop
    after
        0 -> continue
    end.

recv_loop(continue, #state{mod=Mod, mod_state=ModState}=State) ->
    handle_recv(Mod:recv_nowait(ModState), maybe_log(State));
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
    sleep_poll_interval(State),
    recv_loop(set_mod_state(ModState, State)).

increment_msg_count(#state{msg_count=Count}=S) ->
    S#state{msg_count=Count + 1}.

set_mod_state(ModState, State) ->
    State#state{mod_state=ModState}.

sleep_poll_interval(#state{poll_interval=I}) ->
    timer:sleep(I).

terminate(#state{mod=Mod, mod_state=ModState}) ->
    Mod:terminate(ModState).
