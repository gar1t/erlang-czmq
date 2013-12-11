-module(czmq_test).

-export([test/0,
         zstr_send_recv/1,
         sendmem_framerecv/1]).

-include("czmq.hrl").

test() ->
    {ok, Ctx} = czmq:start_link(),
    %%zstr_send_recv(Ctx),
    %%sendmem_framerecv(Ctx),
    zauth_test(Ctx),

    %%pong = czmq:ping(Ctx),

    czmq:terminate(Ctx).

%%--------------------------------------------------------------------
%% @doc Tests basic zstr send and receive.
%% @end
%%--------------------------------------------------------------------

zstr_send_recv(Ctx) ->
    Writer = czmq:zsocket_new(Ctx, ?ZMQ_PUSH),
    {ok, Port} = czmq:zsocket_bind(Writer, "tcp://*:*"),

    Reader = czmq:zsocket_new(Ctx, ?ZMQ_PULL),
    ok = czmq:zsocket_connect(Reader, connect_endpoint(Port)),

    Msg = "Watson, I found your shirt",
    ok = czmq:zstr_send(Writer, Msg),

    timer:sleep(100),

    {ok, Msg} = czmq:zstr_recv_nowait(Reader),

    error = czmq:zstr_recv_nowait(Reader),

    czmq:zsocket_destroy(Writer),
    czmq:zsocket_destroy(Reader).

%%--------------------------------------------------------------------
%% @doc Tests sendmem and frame receieves as per
%% http://czmq.zeromq.org/manual:zsocket.
%% @end
%%--------------------------------------------------------------------

sendmem_framerecv(Ctx) ->
    Writer = czmq:zsocket_new(Ctx, ?ZMQ_PUSH),
    "PUSH" = czmq:zsocket_type_str(Writer),
    {ok, Port} = czmq:zsocket_bind(Writer, "tcp://*:*"),

    Reader = czmq:zsocket_new(Ctx, ?ZMQ_PULL),
    "PULL" = czmq:zsocket_type_str(Reader),
    ok = czmq:zsocket_connect(Reader, connect_endpoint(Port)),

    ok = czmq:zsocket_sendmem(Writer, "ABC", ?ZFRAME_MORE),
    ok = czmq:zsocket_sendmem(Writer, "DEFG"),

    timer:sleep(100),

    {ok, Frame1} = czmq:zframe_recv_nowait(Reader),

    <<"ABC">> = czmq:zframe_data(Frame1),
    true = czmq:zframe_more(Frame1),

    {ok, Frame2} = czmq:zframe_recv_nowait(Reader),
    <<"DEFG">> = czmq:zframe_data(Frame2),
    false = czmq:zframe_more(Frame2),

    error = czmq:zframe_recv_nowait(Reader),

    czmq:zsocket_destroy(Writer),
    czmq:zsocket_destroy(Reader).

%%--------------------------------------------------------------------
%% @doc Tests zauth as per http://czmq.zeromq.org/manual:zauth.
%% @end
%%--------------------------------------------------------------------

zauth_test(Ctx) ->
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

    %% Without server config, all clients are denied.
    false = client_server_can_connect(Ctx, PlainConfig("admin", "Password")),

    %% Write a password file.
    TmpDir = create_tmp_dir(),
    PwdFile = password_file(TmpDir),
    write_password_file(PwdFile, [{"admin", "Password"}]),

    %% With server config only matching credentials are allowed.
    czmq:zauth_configure_plain(Auth, "*", PwdFile),
    true = client_server_can_connect(Ctx, PlainConfig("admin", "Password")),
    false = client_server_can_connect(Ctx, PlainConfig("admin", "Bogus")),

    delete_dir(TmpDir),
    czmq:zauth_destroy(Auth).

create_tmp_dir() ->
    Dir = "/tmp/czmq_test",
    handle_make_dir(file:make_dir(Dir), Dir).

handle_make_dir(ok, Dir) -> Dir;
handle_make_dir({error, eexist}, Dir) -> Dir.

password_file(Dir) ->
    filename:join(Dir, "password-file").

delete_dir(Dir) when Dir /= "/" ->
    "" = os:cmd("rm -rf " ++ Dir).

write_password_file(File, Creds) ->
    Bytes = [[User, "=", Pwd, "\n"] || {User, Pwd} <- Creds],
    ok = file:write_file(File, Bytes).

client_server_can_connect(Ctx, Config) ->
    Server = czmq:zsocket_new(Ctx, ?ZMQ_PUSH),
    Client = czmq:zsocket_new(Ctx, ?ZMQ_PULL),

    ok = Config(Client, Server),

    {ok, Port} = czmq:zsocket_bind(Server, "tcp://127.0.0.1:*"),
    ok = czmq:zsocket_connect(Client, connect_endpoint(Port)),

    Result = try_connect(Client, Server),

    czmq:zsocket_destroy(Server),
    czmq:zsocket_destroy(Client),
    
    Result.

try_connect(Client, Server) ->
    ok = czmq:zstr_send(Server, "Watson, sorry about the other night"),
    timer:sleep(100),
    case czmq:zstr_recv_nowait(Client) of
        {ok, _} -> true;
        error -> false
    end.

connect_endpoint(Port) ->
    "tcp://127.0.0.1:" ++ integer_to_list(Port).
