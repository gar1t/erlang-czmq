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
         zsocket_set_zap_domain/2,
         zsocket_set_plain_server/2,
         zsocket_set_plain_username/2,
         zsocket_set_plain_password/2,
         zsocket_set_curve_server/2,
         zsocket_set_curve_serverkey/2,
         zstr_send/2,
         zstr_recv_nowait/1,
         zframe_recv_nowait/1,
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
-define(CMD_ZSOCKOPT_SET_STR,        7).
-define(CMD_ZSOCKOPT_SET_INT,        8).
-define(CMD_ZSTR_SEND,               9).
-define(CMD_ZSTR_RECV_NOWAIT,       10).
-define(CMD_ZFRAME_RECV_NOWAIT,     11).
-define(CMD_ZAUTH_NEW,              12).
-define(CMD_ZAUTH_DENY,             13).
-define(CMD_ZAUTH_ALLOW,            14).
-define(CMD_ZAUTH_CONFIGURE_PLAIN,  15).
-define(CMD_ZAUTH_CONFIGURE_CURVE,  16).
-define(CMD_ZAUTH_DESTROY,          17).
-define(CMD_ZCERT_NEW,              18).
-define(CMD_ZCERT_APPLY,            19).
-define(CMD_ZCERT_PUBLIC_TXT,       20).
-define(CMD_ZCERT_SAVE_PUBLIC,      21).
-define(CMD_ZCERT_DESTROY,          22).

%% These *must* correspond to the ZSOCKOPT_XXX definitions in czmq_port.c
-define(ZSOCKOPT_ZAP_DOMAIN, 0).
-define(ZSOCKOPT_PLAIN_SERVER, 1).
-define(ZSOCKOPT_PLAIN_USERNAME, 2).
-define(ZSOCKOPT_PLAIN_PASSWORD, 3).
-define(ZSOCKOPT_CURVE_SERVER, 4).
-define(ZSOCKOPT_CURVE_SERVERKEY, 5).

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
    bound_socket(Socket, Ctx).

bound_socket(Socket, Ctx) -> {Ctx, Socket}.

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

zsocket_set_zap_domain({Ctx, Socket}, Domain) ->
    Args = {Socket, ?ZSOCKOPT_ZAP_DOMAIN, Domain},
    gen_server:call(Ctx, {?CMD_ZSOCKOPT_SET_STR, Args}, infinity).

zsocket_set_plain_server({Ctx, Socket}, Flag) ->
    Args = {Socket, ?ZSOCKOPT_PLAIN_SERVER, bool_to_int(Flag)},
    gen_server:call(Ctx, {?CMD_ZSOCKOPT_SET_INT, Args}, infinity).

bool_to_int(true) -> 1;
bool_to_int(false) -> 0.

zsocket_set_plain_username({Ctx, Socket}, Username) ->
    Args = {Socket, ?ZSOCKOPT_PLAIN_USERNAME, Username},
    gen_server:call(Ctx, {?CMD_ZSOCKOPT_SET_STR, Args}, infinity).

zsocket_set_plain_password({Ctx, Socket}, Password) ->
    Args = {Socket, ?ZSOCKOPT_PLAIN_PASSWORD, Password},
    gen_server:call(Ctx, {?CMD_ZSOCKOPT_SET_STR, Args}, infinity).

zsocket_set_curve_server({Ctx, Socket}, Flag) ->
    Args = {Socket, ?ZSOCKOPT_CURVE_SERVER, bool_to_int(Flag)},
    gen_server:call(Ctx, {?CMD_ZSOCKOPT_SET_INT, Args}, infinity).

zsocket_set_curve_serverkey({Ctx, Socket}, Key) when is_list(Key) ->
    Args = {Socket, ?ZSOCKOPT_CURVE_SERVERKEY, Key},
    gen_server:call(Ctx, {?CMD_ZSOCKOPT_SET_STR, Args}, infinity).

zstr_send({Ctx, Socket}, Data) ->
    gen_server:call(Ctx, {?CMD_ZSTR_SEND, {Socket, Data}}, infinity).

zstr_recv_nowait({Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZSTR_RECV_NOWAIT, {Socket}}, infinity).

zframe_recv_nowait({Ctx, Socket}) ->
    gen_server:call(Ctx, {?CMD_ZFRAME_RECV_NOWAIT, {Socket}}, infinity).

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

subscribe({Ctx, _}=Socket, Options) ->
    czmq_poller:start(Socket, Ctx, Options).

subscribe_link(Socket) -> subscribe_link(Socket, []).

subscribe_link({Ctx, _}=Socket, Options) ->
    czmq_poller:start_link(Socket, Ctx, Options).

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
