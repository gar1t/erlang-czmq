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

czmq:subscribe(C, Reader),
Msg = "Watson, I found your flogger",
czmq:zstr_send(C, Writer, Msg),
receive
    Msg -> ok
after
    100 -> error(not_delivered)
end
```

I think the best way to implement this is to use a separate process (e.g. a
timer czmq_poller) to poll the socket and send received messages to a registred
process. This process would monitor both the czmq process and the subscriber
process and terminate if either of those terminated.

## Simplest Possible Thing That Could Work

See src/czmq_test.erl for tests.

## Performance

We should provide some comparison benchmarks on the performance of this binding
versus the standard bindings here:

    git clone git://github.com/zeromq/erlzmq2.git

Here's what we should test:

- Received messages per second for some message size
- Delivered messages per second for some message size

To remove language variances, we should use a C program to send and receive
messages.

### Test 1

    Push (Erlang) -----> Pull (C)

In this case, the C program would run in a blocking recv and track the number
of messages received, printing a total an incremental count every second.

### Test 2

    Pull (Erlang) <----- Push (C)

In this case, the Erlang program would run in a non blocking recv and track
messages received, printing the total and incremental count every second.

### Test 3

We might also use a dealer / router pair to test a request/response exchange.

      Dealer (Erlang) ----> Router (C)
	        ^                  |
            |__________________|
