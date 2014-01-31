%% ===================================================================
%% @author Garrett Smith <g@rre.tt>
%% @copyright 2014 Garrett Smith
%%
%% @doc Tests for erlang-czmq.
%%
%% @end
%% ===================================================================

-module(czmq_test).

-export([test/0,
         zstr_send_recv/1,
         sendmem_framerecv/1,
         zauth/1,
         poller/1,
         router_dealer/1,
         sockopts/1]).

-include("czmq.hrl").

test() ->
    io:format("Testing erlang-czmq...~n"),
    {ok, Ctx} = czmq:start_link(),
    zstr_send_recv(Ctx),
    sendmem_framerecv(Ctx),
    zauth(Ctx),
    poller(Ctx),
    router_dealer(Ctx),
    sockopts(Ctx),
    czmq:terminate(Ctx).

%%--------------------------------------------------------------------
%% @doc Tests basic zstr send and receive.
%% @end
%%--------------------------------------------------------------------

zstr_send_recv(Ctx) ->
    io:format(" * zstr_send_recv: "),

    Writer = czmq:zsocket_new(Ctx, ?ZMQ_PUSH),
    {ok, Port} = czmq:zsocket_bind(Writer, "tcp://*:*"),

    Reader = czmq:zsocket_new(Ctx, ?ZMQ_PULL),
    ok = czmq:zsocket_connect(Reader, connect_endpoint(Port)),

    timer:sleep(10),

    Msg = "Watson, I found your shirt",
    ok = czmq:zstr_send(Writer, Msg),

    timer:sleep(10),

    {ok, Msg} = czmq:zstr_recv_nowait(Reader),

    error = czmq:zstr_recv_nowait(Reader),

    czmq:zsocket_destroy(Writer),
    czmq:zsocket_destroy(Reader),

    io:format("ok~n").

%%--------------------------------------------------------------------
%% @doc Tests sendmem and frame receieves as per
%% http://czmq.zeromq.org/manual:zsocket.
%% @end
%%--------------------------------------------------------------------

sendmem_framerecv(Ctx) ->
    io:format(" * sendmem_framerecv: "),

    Writer = czmq:zsocket_new(Ctx, ?ZMQ_PUSH),
    "PUSH" = czmq:zsocket_type_str(Writer),
    {ok, Port} = czmq:zsocket_bind(Writer, "tcp://*:*"),

    Reader = czmq:zsocket_new(Ctx, ?ZMQ_PULL),
    "PULL" = czmq:zsocket_type_str(Reader),
    ok = czmq:zsocket_connect(Reader, connect_endpoint(Port)),

    timer:sleep(10),

    ok = czmq:zsocket_sendmem(Writer, "ABC", ?ZFRAME_MORE),
    ok = czmq:zsocket_sendmem(Writer, "DEFG"),

    timer:sleep(10),

    {ok, Frame1} = czmq:zframe_recv_nowait(Reader),

    <<"ABC">> = czmq:zframe_data(Frame1),
    true = czmq:zframe_more(Frame1),

    {ok, Frame2} = czmq:zframe_recv_nowait(Reader),
    <<"DEFG">> = czmq:zframe_data(Frame2),
    false = czmq:zframe_more(Frame2),

    error = czmq:zframe_recv_nowait(Reader),

    czmq:zsocket_destroy(Writer),
    czmq:zsocket_destroy(Reader),

    io:format("ok~n").

%%--------------------------------------------------------------------
%% @doc Tests zauth as per http://czmq.zeromq.org/manual:zauth.
%% @end
%%--------------------------------------------------------------------

zauth(Ctx) ->
    io:format(" * zauth: "),

    Auth = czmq:zauth_new(Ctx),

    %% Default is to accept all clients.
    NullConfig = fun(_Client, _Server) -> ok end,
    true = client_server_can_connect(Ctx, NullConfig),

    %% Setting a domain turns on auth but without policies, clients
    %% are allowed.
    DomainConfig =
        fun(_Client, Server) ->
                czmq:zsocket_set_zap_domain(Server, "global")
        end,
    true = client_server_can_connect(Ctx, DomainConfig),

    %% Blacklist 127.0.0.1, connection should fail.
    czmq:zauth_deny(Auth, "127.0.0.1"),
    false = client_server_can_connect(Ctx, DomainConfig),

    %% Whitelist our address, which overrides the blacklist.
    czmq:zauth_allow(Auth, "127.0.0.1"),
    true = client_server_can_connect(Ctx, DomainConfig),

    %% PLAIN auth
    PlainConfig =
        fun(Username, Password) ->
                fun(Client, Server) ->
                        czmq:zsocket_set_plain_server(Server, true),
                        czmq:zsocket_set_plain_username(Client, Username),
                        czmq:zsocket_set_plain_password(Client, Password)
                end
        end,

    %% Without authentication configured, all clients are denied.
    false = client_server_can_connect(Ctx, PlainConfig("admin", "Password")),

    %% Write a password file.
    TmpDir = create_tmp_dir(),
    PwdFile = filename:join(TmpDir, "password-file"),
    write_password_file(PwdFile, [{"admin", "Password"}]),

    %% With server config only matching credentials are allowed.
    czmq:zauth_configure_plain(Auth, "*", PwdFile),
    true = client_server_can_connect(Ctx, PlainConfig("admin", "Password")),
    false = client_server_can_connect(Ctx, PlainConfig("admin", "Bogus")),

    %% CURVE authentication
    ServerCert = czmq:zcert_new(Ctx),
    ClientCert = czmq:zcert_new(Ctx),

    CurveConfig =
        fun(Client, Server) ->
                %% Server config
                czmq:zcert_apply(ServerCert, Server),
                czmq:zsocket_set_curve_server(Server, true),

                %% Client config
                czmq:zcert_apply(ClientCert, Client),
                {ok, ServerKey} = czmq:zcert_public_txt(ServerCert),
                czmq:zsocket_set_curve_serverkey(Client, ServerKey)
        end,

    %% Without authentication configured, all clients are denied.
    false = client_server_can_connect(Ctx, CurveConfig),

    %% Configure curve to allow any
    czmq:zauth_configure_curve(Auth, "*", ?CURVE_ALLOW_ANY),
    true = client_server_can_connect(Ctx, CurveConfig),

    %% Specifying a location with no valid certs, clients are defined.
    czmq:zauth_configure_curve(Auth, "*", TmpDir),
    false = client_server_can_connect(Ctx, CurveConfig),

    %% Location with a valid cert, client is allowed.
    ClientCertFile = filename:join(TmpDir, "mycert.txt"),
    czmq:zcert_save_public(ClientCert, ClientCertFile),
    true = client_server_can_connect(Ctx, CurveConfig),

    %% Remove valid cert, client is once again denied.
    delete_file(ClientCertFile),
    false = client_server_can_connect(Ctx, CurveConfig),

    czmq:zcert_destroy(ServerCert),
    czmq:zcert_destroy(ClientCert),

    %% Remove authentication - clients are allowed.
    czmq:zauth_destroy(Auth),
    true = client_server_can_connect(Ctx, NullConfig),

    %% Cleanup
    delete_dir(TmpDir),
    czmq:zauth_destroy(Auth),

    io:format("ok~n").

create_tmp_dir() ->
    Dir = "/tmp/czmq_test",
    handle_make_dir(file:make_dir(Dir), Dir).

handle_make_dir(ok, Dir) -> Dir;
handle_make_dir({error, eexist}, Dir) -> Dir.

delete_dir(Dir) when Dir /= "/" ->
    "" = os:cmd("rm -rf " ++ Dir).

delete_file(File) ->
    "" = os:cmd("rm " ++ File).

write_password_file(File, Creds) ->
    Bytes = [[User, "=", Pwd, "\n"] || {User, Pwd} <- Creds],
    ok = file:write_file(File, Bytes).

client_server_can_connect(Ctx, Config) ->
    Server = czmq:zsocket_new(Ctx, ?ZMQ_PUSH),
    Client = czmq:zsocket_new(Ctx, ?ZMQ_PULL),

    ok = Config(Client, Server),

    {ok, Port} = czmq:zsocket_bind(Server, "tcp://127.0.0.1:*"),
    ok = czmq:zsocket_connect(Client, connect_endpoint(Port)),

    timer:sleep(10),

    Sent = czmq:zstr_send(Server, "Watson, sorry about the other night"),

    timer:sleep(10),

    Received = czmq:zstr_recv_nowait(Client),

    czmq:zsocket_destroy(Server),
    czmq:zsocket_destroy(Client),

    msg_sent_and_received(Sent, Received).

msg_sent_and_received(ok, {ok, _}) -> true;
msg_sent_and_received(_Sent, _Received) -> false.

connect_endpoint(Port) ->
    "tcp://127.0.0.1:" ++ integer_to_list(Port).

%%--------------------------------------------------------------------
%% @doc Tests using a poller process to recv and dispatch messages.
%% @end
%%--------------------------------------------------------------------

poller(Ctx) ->
    io:format(" * poller: "),

    Reader = czmq:zsocket_new(Ctx, ?ZMQ_PULL),
    {ok, _} = czmq:zsocket_bind(Reader, "inproc://zpoller_test"),

    Writer = czmq:zsocket_new(Ctx, ?ZMQ_PUSH),
    czmq:zsocket_set_sndhwm(Writer, 5000),
    ok = czmq:zsocket_connect(Writer, "inproc://zpoller_test"),

    {ok, Poller} = czmq:subscribe_link(Reader, [{poll_interval, 100}]),

    MsgFmt = "Watson, I want you in ~b second(s)",
    send_messages(Writer, MsgFmt, 5000),
    receive_messages(MsgFmt, 5000),

    czmq:unsubscribe(Poller),
    czmq:zsocket_destroy(Reader),
    czmq:zsocket_destroy(Writer),

    io:format("ok~n").

send_messages(_Socket, _MsgFmt, 0) -> ok;
send_messages(Socket, MsgFmt, N) when N > 0 ->
    Msg = io_lib:format(MsgFmt, [N]),
    ok = czmq:zstr_send(Socket, Msg),
    send_messages(Socket, MsgFmt, N - 1).

receive_messages(_MsgFmt, 0) -> ok;
receive_messages(MsgFmt, N) when N > 0 ->
    Expected = [iolist_to_binary(io_lib:format(MsgFmt, [N]))],
    receive
        Expected -> ok
    after
        1000 -> error({timeout, N})
    end,
    receive_messages(MsgFmt, N - 1).

%%--------------------------------------------------------------------
%% @doc Tests router/dealer interactions.
%% @end
%%--------------------------------------------------------------------

router_dealer(Ctx) ->
    io:format(" * router_dealer: "),

    Router = czmq:zsocket_new(Ctx, ?ZMQ_ROUTER),
    {ok, 0} = czmq:zsocket_bind(Router, "inproc://router_dealer"),

    Dealer1 = czmq:zsocket_new(Ctx, ?ZMQ_DEALER),
    ok = czmq:zsocket_connect(Dealer1, "inproc://router_dealer"),

    Dealer2 = czmq:zsocket_new(Ctx, ?ZMQ_DEALER),
    ok = czmq:zsocket_connect(Dealer2, "inproc://router_dealer"),

    ok = czmq:zstr_send(Dealer1, "dealer-1 says hello"),
    ok = czmq:zstr_send(Dealer2, "dealer-2 says hi"),

    timer:sleep(100),

    %% Routers recv messages preceded by dealer ID frame.

    {ok, [Dealer1Ref, <<"dealer-1 says hello">>]} =
        czmq:zframe_recv_all(Router),

    {ok, [Dealer2Ref, <<"dealer-2 says hi">>]} =
        czmq:zframe_recv_all(Router),

    error = czmq:zframe_recv_all(Router),

    %% Use dealer IDs to router messages to specific dealers.

    ok = czmq:zsocket_send_all(Router, [Dealer1Ref, "hello dealer-1"]),
    ok = czmq:zsocket_send_all(Router, [Dealer2Ref, "hi dealer-2"]),

    timer:sleep(100),

    {ok, [<<"hello dealer-1">>]} = czmq:zframe_recv_all(Dealer1),
    {ok, [<<"hi dealer-2">>]} = czmq:zframe_recv_all(Dealer2),

    czmq:zsocket_destroy(Router),
    czmq:zsocket_destroy(Dealer1),
    czmq:zsocket_destroy(Dealer2),

    io:format("ok~n").

%%--------------------------------------------------------------------
%% @doc Tests sockopt API.
%% @end
%%--------------------------------------------------------------------

sockopts(Ctx) ->
    io:format(" * sockopts: "),

    %% TODO: This is an incomplete test.

    Sock = czmq:zsocket_new(Ctx, ?ZMQ_ROUTER),

    %% Backlog
    100 = czmq:zsocket_backlog(Sock),
    czmq:zsocket_set_backlog(Sock, 200),
    200 = czmq:zsocket_backlog(Sock),

    %% HWMs
    1000 = czmq:zsocket_sndhwm(Sock),
    czmq:zsocket_set_sndhwm(Sock, 2000),
    2000 = czmq:zsocket_sndhwm(Sock),

    1000 = czmq:zsocket_rcvhwm(Sock),
    czmq:zsocket_set_rcvhwm(Sock, 3000),
    3000 = czmq:zsocket_rcvhwm(Sock),

    czmq:zsocket_destroy(Sock),

    io:format("ok~n").
