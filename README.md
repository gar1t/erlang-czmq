# Erlang to CZMQ Bindings

Goals:

- Provide a canonical CZMQ interface from Erlang
- Safe: bugs, errors, assertion failures in CZMQ must not crash Erlang
- Reasonably performant

Non Goals:

- Value atop CZMQ - this is left to applications
- Performance at the expense of safety

## Approach

The "bindings" (this is a lose term given the approach here) should be
implemented as a C Port to ensure that crashes don't effect the Erlang VM.

### Port to CZMQ Mapping

The port will manage a single ZMQ context. All context managed state will
therefore be associated with a port.

### State Management

The port should manage its state appropriately:

- ZMQ context
- Auth objects

...

Use dynamic arrays (vectors) to store references to ZMQ and CZMQ
objects. Objects will be referenced using their array index.

Destroying an object should result in the array elements being set to NULL.

Alternatively we could use the ztree class and store objects with prefixed
names.

TBD

### Sockets - Sending and Receiving

The C port interface provides a synchronous request/response protocol. This
means we need to poll for received messages.

It's nice in Erlang however to have messages simply delivered, rather than to
have to poll for them.

Something like this:

``` erlang
{ok, C} = czmq:start(),
Writer = czmq:zsocket_new(C, ?ZMQ_PUSH),
czmq:zsocket_bind(C, Writer, "tcp://*:1020"),
Reader = czmq:zsocket_new(C, ?ZMQ_PULL),
czmq:zsocket_connect(C, Reader, "tcp://localhost:1020"),

czmq:subscribe(C, Reader, self(),
Msg = "Watson, I found your flogger",
czmq:zstr_send(C, Writer, Msg),
receive
    Msg -> ok
after
    100 -> error(not_delivered)
end
```

## Simplest Possible Thing That Could Work

``` erlang
{ok, C} = czmq:start(),


```
