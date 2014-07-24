%% ===================================================================
%% @author Garrett Smith <g@rre.tt>
%% @copyright 2014 Garrett Smith
%%
%% @doc Polling process for socket messages.
%%
%% As erlang-czmq is implemented as an external port, it uses all.
%% non blocking operations. Message devliery must be performed by
%% routinely polling a socket.
%%
%% @end
%% ===================================================================

-module(czmq_poller).

-behavior(gen_server).

-export([start/2, start_link/2, stop/2, stop/1]).

-export([init/1, handle_info/2, handle_cast/2, handle_call/3,
         terminate/2, code_change/3]).

-record(state, {socket, dispatch, interval, start}).

-define(DEFAULT_POLL_INTERVAL, 1000).

%%%===================================================================
%%% Start / init
%%%===================================================================

start(Socket, Opts) ->
    start(Socket, check_opts(Opts), opt(non_block, Opts)).

start_link(Socket, Opts) ->
    start_link(Socket, check_opts(Opts), opt(non_block, Opts)).

start(Socket, Opts, true) ->
    czmq:zpoller_new(Socket, opt(target, Opts));
start(Socket, Opts, false) ->
    {ok, Pid} = gen_server:start(?MODULE, [Socket, Opts], []),
    Pid.
   
start_link(Socket, Opts, true) ->
    czmq:zpoller_new(Socket, opt(target, Opts));
start_link(Socket, Opts, false) ->
    {ok, Pid} = gen_server:start_link(?MODULE, [Socket, check_opts(Opts)], []),
    Pid.

init([Socket, Opts]) ->
    Pid      = opt(target, Opts),
    Fun      = opt(dispatch_fun, Opts),
    Interval = opt(interval, Opts),

    maybe_monitor(Pid),

    Start = timestamp(),
    {ok, #state {
        socket   = Socket,
        dispatch = Fun,
        interval = Interval,
        start    = Start},
    0}.

check_opts(Opts) ->
    check_opts(target, proplists:get_value(target, Opts), Opts).

check_opts(target, undefined, Opts) ->
    [{target, self()} | Opts];
check_opts(target, _, Opts) ->
    Opts.

opt(non_block, Opts) ->
    lists:member(non_block, Opts);
opt(interval, Opts) ->
    proplists:get_value(interval, Opts, ?DEFAULT_POLL_INTERVAL);
opt(target, Opts) ->
    proplists:get_value(target, Opts);
opt(dispatch_fun, Opts) ->
    opt(dispatch_fun, proplists:get_value(dispatch_fun, Opts), Opts).

opt(dispatch_fun, undefined, Opts) ->
    Pid = opt(target, Opts),
    fun(Msg) -> erlang:send(Pid, {self(), Msg}) end;
opt(dispatch_fun, Fun, _Opts) ->
    Fun.

maybe_monitor(undefined) -> ok;
maybe_monitor(Pid) -> erlang:monitor(process, Pid).

timestamp() ->
    {M, S, U} = erlang:now(),
    M * 1000000000 + S * 1000 + U div 1000.

%%%===================================================================
%%% API
%%%===================================================================

stop(Poller, true) ->
    czmq:zpoller_destroy(Poller);
stop(Poller, false) ->
    stop(Poller);
stop(Poller, Opts) when is_list(Opts) ->
    stop(Poller, lists:member(non_block, Opts)).

stop(Poller) ->
    gen_server:call(Poller, stop).

%%%===================================================================
%%% Message dispatch
%%%===================================================================

handle_info(timeout, State) ->
    handle_poll(State);
handle_info({'DOWN', _Ref, process, _Proc, _Reason}, State) ->
    {stop, normal, State}.

%%%===================================================================
%%% Poll for / dispatch messages
%%%===================================================================

handle_poll(State) ->
    dispatch_messages(State),
    schedule_next(State),
    {noreply, State}.

dispatch_messages(State) ->
    handle_recv_msg(recv_msg(State, []), State).

recv_msg(State, FramesAcc) ->
    handle_recv_frame(recv_frame(State), State, FramesAcc).

recv_frame(#state{socket=Socket}) ->
    czmq:zframe_recv_nowait(Socket).

handle_recv_frame({ok, {Data, More}}, State, FramesAcc) ->
    handle_frame_more(More, State, [Data|FramesAcc]);
handle_recv_frame(error, _State, _FramesAcc) ->
    error.

handle_frame_more(true, State, FramesAcc) ->
    handle_recv_frame(recv_frame(State), State, FramesAcc);
handle_frame_more(false, _State, FramesAcc) ->
    {ok, lists:reverse(FramesAcc)}.

handle_recv_msg({ok, Msg}, State) ->
    dispatch_msg(Msg, State),
    dispatch_messages(State);
handle_recv_msg(error, _State) ->
    ok.

dispatch_msg(Msg, #state{dispatch=Dispatch}) ->
    Dispatch(Msg).

schedule_next(State) ->
    erlang:send_after(next_delay(State), self(), timeout).

next_delay(#state{start=Start, interval=Interval}) ->
    Now = timestamp(),
    ((Now - Start) div Interval + 1) * Interval + Start - Now.

%%%===================================================================
%%% Handle stop
%%%===================================================================

handle_call(stop, _From, State) ->
    {stop, normal, ok, State}.

%%%===================================================================
%%% gen_server boilderplate
%%%===================================================================

handle_cast(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
