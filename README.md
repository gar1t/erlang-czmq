# Erlang to CZMQ Bindings

Goals:

- Provide a canonical CZMQ interface from Erlang
- Safe: bugs, errors, assertion failures in CZMQ must not crash Erlang
- Reasonably performant

Non Goals:

- Value atop CZMQ - this is left to applications
- Performance at the expense of safety

## Approach

The "bindings" (this is a lose term given the approach here) are
implemented as a C Port to ensure that crashes don't effect the Erlang VM.

The API mirrors that of CZMQ with all functions being available through the
`czmq`module.

### Port to CZMQ Mapping

The port manages a single ZMQ context. All context managed state is associated
with a port.

The port manages its state appropriately:

- ZMQ context
- Sockets
- Auth object (limited to one per context)
- Certs

We use dynamic arrays (vectors) to store references to ZMQ and CZMQ
objects. Objects are referenced using their array index.

When an object is destroyed, it's associated element in the applicable array is
set to NULL.

### Sockets - Sending and Receiving

Erlang C ports use a synchronous request/response protocol over standard input
output. This makes them unsuitable for handling the asynchronous events that
are endemic to ZeroMQ. Received events must be routinely polled using non
blocking operations.

Messages can be checked explicitly or routinely using `czmq_poller`. Messages
received by `czmq_poller` can be delivered as Erlang messages to another
process, effectively simulating asynchronous message delivery, albiet with some
latency introduced by the polling sleep interval.

## Using `erlang-czmq`

## Benchmarks

While safety is the prime consideration for this binding, performance is
important as well. `erlang-czmq` provides a simple framework for measuring
message send/receive throughput using different bindings.

Benchmarks follow this approach:

- A receiver binds to a local port and receives messages as quickly as it can,
  printing the number of received messages per second.
- A sender connects to the receiver port and sends messages as quickly as it
  can for a period of time.

This scheme can be used to test different combinations of bindings for sending
and receiving. Below are some preliminary results, which are useful as a rough
gage for the relative performance differences of bindings.

### C Receiver / C Sender

To test the native (i.e C) performance of CZMQ, use `czmq-benchmark` located in
`priv` after compiling `erlang-czmq`. First, start the receiver:

    $ cd erlang-czmq/priv
    $ ./czmq-benchmark recv

The receiver will print the total number of messages it receives for each
interval.

Next, in a separate shell, start the sender:

    $ cd erlang-czmq/priv
	$ ./czmq-benchmark send

You will see the number of messages the receiver received during the time the
sender was sending. Discard the first and last observations as they reflect
partial intervals.

### C Receiver / erlang-czmq Sender

This test measures the throughput of using an `erlang-czmq` sender with a C
receiver.

Start the receiver as with the C / C test above.

Next,

### Benchark Summary - Lenovo X220 at 2.7 GHz

    | Recv / Send               | Average MPS | N |
	|---------------------------|-------------|---|
    | C / C                     |     1190500 | 5 |
    | C / erlzmq                |      128136 | 5 |
	| C / erlang-czmq           |       35990 | 5 |
	| erlzmq / C                |      152678 | 5 |
	| erlang-czmq / C           |       10126 | 5 |
	| erlzmq / erlzmq           |      134234 | 5 |
	| erlang-czmq / erlang-czmq |        9614 | 5 |
