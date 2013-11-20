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

The port should manage its state appropriately:

- ZMQ context objects
- Auth objects

...

Use dynamic arrays (vectors) to store references to ZMQ and CZMQ
objects. Objects will be referenced using their array index.

Destroying an object should result in the array elements being set to NULL.

## API

``` erlang
Auth = czmq_auth:new(Context),
czmq_auth:allow(Auth, "192.168.0.1"),
czmq_auth:deny(Auth, "10.0.0.1")
```
