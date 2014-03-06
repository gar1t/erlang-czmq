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

-export([start/2, start_link/2, stop/1]).

-export([init/1, handle_info/2, handle_cast/2, handle_call/3,
         terminate/2, code_change/3]).

-record(state, {socket, dispatch, interval, start}).

-define(DEFAULT_POLL_INTERVAL, 1000).

%%%===================================================================
%%% Start / init
%%%===================================================================

start(Socket, Options) ->
    gen_server:start(?MODULE, [Socket, Options, self()], []).

start_link(Socket, Options) ->
    gen_server:start_link(?MODULE, [Socket, Options, self()], []).

init([Socket, Options, Parent]) ->
    DispatchOption = dispatch_option(Options),
    Target = maybe_target(DispatchOption, Options, Parent),
    maybe_monitor(Target),
    DispatchFun = dispatch_fun(DispatchOption, Target),
    Interval = poll_interval_option(Options),
    Start = timestamp(),
    State = #state{
               socket=Socket,
               dispatch=DispatchFun,
               interval=Interval,
               start=Start},
    {ok, State, 0}.

dispatch_option(Options) ->
    proplists:get_value(dispatch, Options).

maybe_target(undefined, Options, Parent) ->
    proplists:get_value(target, Options, Parent);
maybe_target(_Dispatch, _Options, _Parent) ->
    undefined.

maybe_monitor(undefined) -> ok;
maybe_monitor(Pid) -> erlang:monitor(process, Pid).

dispatch_fun(undefined, Target) ->
    fun(Msg) -> erlang:send(Target, Msg) end;
dispatch_fun(Dispatch, _Target) ->
    Dispatch.

poll_interval_option(Options) ->
    proplists:get_value(poll_interval, Options, ?DEFAULT_POLL_INTERVAL).

timestamp() ->
    {M, S, U} = erlang:now(),
    M * 1000000000 + S * 1000 + U div 1000.

%%%===================================================================
%%% API
%%%===================================================================

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
