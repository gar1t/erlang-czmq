%% ===================================================================
%% @author Garrett Smith <g@rre.tt>
%% @copyright 2014 Garrett Smith
%%
%% @doc czmq interface (facade).
%%
%% All czmq operations are accessed via this module. Refer to docs,
%% tests, and sample code for more information.
%%
%% @end
%% ===================================================================

-module(czmq).

-behavior(gen_server).

-export([start/0, start_link/0,
         ping/1, ping/2,
         zctx_set_iothreads/2,
         zctx_set_linger/2,
         zctx_set_pipehwm/2,
         zctx_set_sndhwm/2,
         zctx_set_rcvhwm/2,
         zsocket_new/2,
         zsocket_type_str/1,
         zsocket_bind/2,
         zsocket_unbind/2,
         zsocket_connect/2,
         zsocket_disconnect/2,
         zsocket_sendmem/2,
         zsocket_sendmem/3,
         zsocket_send_all/2,
         zsocket_destroy/1,
         zsocket_sndhwm/1,
         zsocket_rcvhwm/1,
         zsocket_backlog/1,
         zsocket_set_zap_domain/2,
         zsocket_set_plain_server/2,
         zsocket_set_plain_username/2,
         zsocket_set_plain_password/2,
         zsocket_set_curve_server/2,
         zsocket_set_curve_serverkey/2,
         zsocket_set_sndhwm/2,
         zsocket_set_rcvhwm/2,
         zsocket_set_backlog/2,
         zsocket_set_subscribe/2,
         zsocket_set_unsubscribe/2,
         zstr_send/2,
         zstr_recv_nowait/1,
         zstr_recv/1,
         zstr_recv/2,
         zframe_recv_nowait/1,
         zframe_recv_all/1,
         zframe_data/1,
         zframe_more/1,
         zauth_new/1,
         zauth_deny/2,
         zauth_allow/2,
         zauth_configure_plain/3,
         zauth_configure_curve/3,
         zauth_destroy/1,
         zcert_new/1,
         zcert_apply/2,
         zcert_public_txt/1,
         zcert_save_public/2,
         zcert_destroy/1,
         subscribe/1, subscribe/2,
         subscribe_link/1, subscribe_link/2,
         unsubscribe/1,
         terminate/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("czmq.hrl").

-record(state, {port}).

-define(DEFAULT_PING_TIMEOUT, 1000).
-define(MSG_TIMEOUT, 1000).

%% These *must* correspond to the handlers in czmq_port.c
-define(CMD_PING,                    0).
-define(CMD_ZSOCKET_NEW,             1).
-define(CMD_ZSOCKET_TYPE_STR,        2).
-define(CMD_ZSOCKET_BIND,            3).
-define(CMD_ZSOCKET_CONNECT,         4).
-define(CMD_ZSOCKET_SENDMEM,         5).
-define(CMD_ZSOCKET_DESTROY,         6).
-define(CMD_ZSOCKOPT_GET_STR,        7).
-define(CMD_ZSOCKOPT_GET_INT,        8).
-define(CMD_ZSOCKOPT_SET_STR,        9).
-define(CMD_ZSOCKOPT_SET_INT,       10).
-define(CMD_ZSTR_SEND,              11).
-define(CMD_ZSTR_RECV_NOWAIT,       12).
-define(CMD_ZFRAME_RECV_NOWAIT,     13).
-define(CMD_ZAUTH_NEW,              14).
-define(CMD_ZAUTH_DENY,             15).
-define(CMD_ZAUTH_ALLOW,            16).
-define(CMD_ZAUTH_CONFIGURE_PLAIN,  17).
-define(CMD_ZAUTH_CONFIGURE_CURVE,  18).
-define(CMD_ZAUTH_DESTROY,          19).
-define(CMD_ZCERT_NEW,              20).
-define(CMD_ZCERT_APPLY,            21).
-define(CMD_ZCERT_PUBLIC_TXT,       22).
-define(CMD_ZCERT_SAVE_PUBLIC,      23).
-define(CMD_ZCERT_DESTROY,          24).
-define(CMD_ZSOCKET_UNBIND,         25).
-define(CMD_ZSOCKET_DISCONNECT,     26).
-define(CMD_ZCTX_SET,               27).


%% These *must* correspond to the ZCTX_SET_XXX definitions in czmq_port.c
-define(ZCTX_SET_IOTHREADS, 0).
-define(ZCTX_SET_LINGER, 1).
-define(ZCTX_SET_PIPEHWM, 2).
-define(ZCTX_SET_SNDHWM, 3).
-define(ZCTX_SET_RCVHWM, 4).

%% These *must* correspond to the ZSOCKOPT_XXX definitions in czmq_port.c
-define(ZSOCKOPT_ZAP_DOMAIN, 0).
-define(ZSOCKOPT_PLAIN_SERVER, 1).
-define(ZSOCKOPT_PLAIN_USERNAME, 2).
-define(ZSOCKOPT_PLAIN_PASSWORD, 3).
-define(ZSOCKOPT_CURVE_SERVER, 4).
-define(ZSOCKOPT_CURVE_SERVERKEY, 5).
-define(ZSOCKOPT_BACKLOG, 6).
-define(ZSOCKOPT_SNDHWM, 7).
-define(ZSOCKOPT_RCVHWM, 8).
-define(ZSOCKOPT_SUBSCRIBE, 9).
-define(ZSOCKOPT_UNSUBSCRIBE, 10).




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


zctx_set_iothreads(Ctx, Val) when is_integer(Val) ->
    zctx_set_int(Ctx, ?ZCTX_SET_IOTHREADS, Val).

zctx_set_linger(Ctx, Val) when is_integer(Val) ->
    zctx_set_int(Ctx, ?ZCTX_SET_LINGER, Val).

zctx_set_pipehwm(Ctx, Val) when is_integer(Val) ->
    zctx_set_int(Ctx, ?ZCTX_SET_PIPEHWM, Val).

zctx_set_sndhwm(Ctx, Val) when is_integer(Val) ->
    zctx_set_int(Ctx, ?ZCTX_SET_SNDHWM, Val).

zctx_set_rcvhwm(Ctx, Val) when is_integer(Val) ->
    zctx_set_int(Ctx, ?ZCTX_SET_RCVHWM, Val).


zctx_set_int(Ctx, Opt, Val) when is_integer(Val) ->
    Args = {Opt, Val},
    gen_server:call(Ctx, {?CMD_ZCTX_SET, Args}, infinity).



zsocket_new(Ctx, Type) when is_atom(Type) ->
    zsocket_new(Ctx, atom_to_socket_type(Type));
zsocket_new(Ctx, Type) ->
    Socket = gen_server:call(Ctx, {?CMD_ZSOCKET_NEW, {Type}}, infinity),
    bound_socket(Socket, Ctx).

atom_to_socket_type(pair)   -> ?ZMQ_PAIR;
atom_to_socket_type(pub)    -> ?ZMQ_PUB;
atom_to_socket_type(sub)    -> ?ZMQ_SUB;
atom_to_socket_type(req)    -> ?ZMQ_REQ;
atom_to_socket_type(rep)    -> ?ZMQ_REP;
atom_to_socket_type(dealer) -> ?ZMQ_DEALER;
atom_to_socket_type(router) -> ?ZMQ_ROUTER;
atom_to_socket_type(pull)   -> ?ZMQ_PULL;
atom_to_socket_type(push)   -> ?ZMQ_PUSH;
atom_to_socket_type(xpub)   -> ?ZMQ_XPUB;
atom_to_socket_type(xsub)   -> ?ZMQ_XSUB;
atom_to_socket_type(stream) -> ?ZMQ_STREAM.

bound_socket(Socket, Ctx) -> {Ctx, Socket}.

zsocket_type_str({Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZSOCKET_TYPE_STR, {Socket}}, infinity).

zsocket_bind({Ctx, Socket}, Endpoint) ->
    gen_server:call(Ctx, {?CMD_ZSOCKET_BIND, {Socket, Endpoint}}, infinity).

zsocket_unbind({Ctx, Socket}, Endpoint) ->
    gen_server:call(Ctx, {?CMD_ZSOCKET_UNBIND, {Socket, Endpoint}}, infinity).

zsocket_connect({Ctx, Socket}, Endpoint) ->
    gen_server:call(Ctx, {?CMD_ZSOCKET_CONNECT, {Socket, Endpoint}}, infinity).

zsocket_disconnect({Ctx, Socket}, Endpoint) ->
    gen_server:call(Ctx, {?CMD_ZSOCKET_DISCONNECT, {Socket, Endpoint}}, infinity).

zsocket_sendmem(BoundSocket, Data) ->
    zsocket_sendmem(BoundSocket, Data, 0).

zsocket_sendmem(BoundSocket, Data, Flag) when is_atom(Flag) ->
    zsocket_sendmem(BoundSocket, Data, atom_to_zframe_flag(Flag));
zsocket_sendmem({Ctx, Socket}, Data, Flags) ->
    DataBin = iolist_to_binary(Data),
    gen_server:call(
      Ctx, {?CMD_ZSOCKET_SENDMEM, {Socket, DataBin, Flags}}, infinity).

atom_to_zframe_flag(more)     -> ?ZFRAME_MORE;
atom_to_zframe_flag(reuse)    -> ?ZFRAME_REUSE;
atom_to_zframe_flag(dontwait) -> ?ZFRAME_DONTWAIT.

zsocket_send_all(BoundSocket, [Last]) ->
    zsocket_sendmem(BoundSocket, Last, 0);
zsocket_send_all(BoundSocket, [Frame|Rest]) ->
    handle_sendmem_all(
      zsocket_sendmem(BoundSocket, Frame, ?ZFRAME_MORE),
      BoundSocket, Rest).

handle_sendmem_all(ok, BoundSocket, Rest) ->
    zsocket_send_all(BoundSocket, Rest);
handle_sendmem_all(Err, _BoundSocket, _Rest) ->
    Err.

zsocket_destroy({Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZSOCKET_DESTROY, {Socket}}, infinity).

sockopt_int({Ctx, Socket}, Opt) ->
    gen_server:call(Ctx, {?CMD_ZSOCKOPT_GET_INT, {Socket, Opt}}, infinity).

zsocket_sndhwm(Sock) ->
    sockopt_int(Sock, ?ZSOCKOPT_SNDHWM).

zsocket_rcvhwm(Sock) ->
    sockopt_int(Sock, ?ZSOCKOPT_RCVHWM).

zsocket_backlog(Sock) ->
    sockopt_int(Sock, ?ZSOCKOPT_BACKLOG).

sockopt_set_str({Ctx, Socket}, Opt, Str) when is_list(Str) ->
    Args = {Socket, Opt, Str},
    gen_server:call(Ctx, {?CMD_ZSOCKOPT_SET_STR, Args}, infinity).

sockopt_set_int({Ctx, Socket}, Opt, Int) when is_integer(Int) ->
    Args = {Socket, Opt, Int},
    gen_server:call(Ctx, {?CMD_ZSOCKOPT_SET_INT, Args}, infinity);
sockopt_set_int(Sock, Opt, true) ->
    sockopt_set_int(Sock, Opt, 1);
sockopt_set_int(Sock, Opt, false) ->
    sockopt_set_int(Sock, Opt, 0).

zsocket_set_zap_domain(Sock, Domain) ->
    sockopt_set_str(Sock, ?ZSOCKOPT_ZAP_DOMAIN, Domain).

zsocket_set_plain_server(Sock, Flag) ->
    sockopt_set_int(Sock, ?ZSOCKOPT_PLAIN_SERVER, Flag).

zsocket_set_plain_username(Sock, Username) ->
    sockopt_set_str(Sock, ?ZSOCKOPT_PLAIN_USERNAME, Username).

zsocket_set_plain_password(Sock, Password) ->
    sockopt_set_str(Sock, ?ZSOCKOPT_PLAIN_PASSWORD, Password).

zsocket_set_curve_server(Sock, Flag) ->
    sockopt_set_int(Sock, ?ZSOCKOPT_CURVE_SERVER, Flag).

zsocket_set_curve_serverkey(Sock, Key) ->
    sockopt_set_str(Sock, ?ZSOCKOPT_CURVE_SERVERKEY, Key).

zsocket_set_sndhwm(Sock, Hwm) ->
    sockopt_set_int(Sock, ?ZSOCKOPT_SNDHWM, Hwm).

zsocket_set_rcvhwm(Sock, Hwm) ->
    sockopt_set_int(Sock, ?ZSOCKOPT_RCVHWM, Hwm).

zsocket_set_backlog(Sock, Backlog) ->
    sockopt_set_int(Sock, ?ZSOCKOPT_BACKLOG, Backlog).

zsocket_set_subscribe(Sock, Subscribe) ->
    sockopt_set_str(Sock, ?ZSOCKOPT_SUBSCRIBE, Subscribe).

zsocket_set_unsubscribe(Sock, Unsubscribe) ->
    sockopt_set_str(Sock, ?ZSOCKOPT_UNSUBSCRIBE, Unsubscribe).

zstr_send({Ctx, Socket}, Data) ->
    gen_server:call(Ctx, {?CMD_ZSTR_SEND, {Socket, Data}}, infinity).

zstr_recv_nowait({Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZSTR_RECV_NOWAIT, {Socket}}, infinity).

zstr_recv(BoundSocket) ->
    zstr_recv(BoundSocket, []).

zstr_recv(BoundSocket, Options) ->
    Poller = start_poller(BoundSocket, Options),
    Reply = zstr_recv_reply(poller_recv(Poller, poll_timeout(Options))),
    stop_poller(Poller),
    Reply.

start_poller(BoundSocket, Options) ->
    {ok, Poller} = czmq_poller:start_link(BoundSocket, Options),
    Poller.

poll_timeout(Options) ->
    proplists:get_value(timeout, Options, infinity).

poller_recv(Poller, Timeout) ->
    receive
        {Poller, Msg} -> {ok, Msg}
    after
        Timeout -> {error, timeout}
    end.

zstr_recv_reply({ok, Parts}) -> {ok, parts_to_list(Parts)};
zstr_recv_reply({error, Err}) -> {error, Err}.

parts_to_list(Parts) ->
    binary_to_list(iolist_to_binary(Parts)).

stop_poller(Poller) ->
    ok = czmq_poller:stop(Poller).

zframe_recv_nowait({Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZFRAME_RECV_NOWAIT, {Socket}}, infinity).

zframe_recv_all(BoundSocket) ->
    handle_frame_recv(
      zframe_recv_nowait(BoundSocket),
      BoundSocket, []).

handle_frame_recv({ok, {Frame, true}}, BoundSocket, Acc) ->
    handle_frame_recv(
      zframe_recv_nowait(BoundSocket),
      BoundSocket, [Frame|Acc]);
handle_frame_recv({ok, {Frame, false}}, _BoundSocket, Acc) ->
    {ok, lists:reverse([Frame|Acc])};
handle_frame_recv(error, _BoundSocket, []) ->
    error.

zframe_data({Data, _More}) -> Data.

zframe_more({_Data, More}) -> More.

zauth_new(Ctx) ->
    Auth = gen_server:call(Ctx, {?CMD_ZAUTH_NEW, {}}, infinity),
    bound_auth(Auth, Ctx).

bound_auth(Auth, Ctx) -> {Ctx, Auth}.

zauth_deny({Ctx, Auth}, Addr) ->
    gen_server:call(Ctx, {?CMD_ZAUTH_DENY, {Auth, Addr}}, infinity).

zauth_allow({Ctx, Auth}, Addr) ->
    gen_server:call(Ctx, {?CMD_ZAUTH_ALLOW, {Auth, Addr}}, infinity).

zauth_configure_plain({Ctx, Auth}, Domain, PwdFile) ->
    gen_server:call(
      Ctx, {?CMD_ZAUTH_CONFIGURE_PLAIN, {Auth, Domain, PwdFile}}).

zauth_configure_curve(BoundAuth, Domain, allow_any) ->
    zauth_configure_curve(BoundAuth, Domain, ?CURVE_ALLOW_ANY);
zauth_configure_curve({Ctx, Auth}, Domain, Location) ->
    gen_server:call(
      Ctx, {?CMD_ZAUTH_CONFIGURE_CURVE, {Auth, Domain, Location}}).

zauth_destroy({Ctx, Auth}) ->
    gen_server:call(Ctx, {?CMD_ZAUTH_DESTROY, {Auth}}, infinity).

zcert_new(Ctx) ->
    Cert = gen_server:call(Ctx, {?CMD_ZCERT_NEW, {}}, infinity),
    bound_cert(Cert, Ctx).

zcert_apply({Ctx, Cert}, {Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZCERT_APPLY, {Cert, Socket}}, infinity).

zcert_public_txt({Ctx, Cert}) ->
    gen_server:call(Ctx, {?CMD_ZCERT_PUBLIC_TXT, {Cert}}, infinity).

zcert_save_public({Ctx, Cert}, File) ->
    gen_server:call(Ctx, {?CMD_ZCERT_SAVE_PUBLIC, {Cert, File}}, infinity).

zcert_destroy({Ctx, Cert}) ->
    gen_server:call(Ctx, {?CMD_ZCERT_DESTROY, {Cert}}, infinity).

bound_cert(Cert, Ctx) -> {Ctx, Cert}.

subscribe(Socket) -> subscribe(Socket, []).

subscribe(Socket, Options) ->
    czmq_poller:start(Socket, Options).

subscribe_link(Socket) -> subscribe_link(Socket, []).

subscribe_link(Socket, Options) ->
    czmq_poller:start_link(Socket, Options).

unsubscribe(Poller) ->
    czmq_poller:stop(Poller).

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
