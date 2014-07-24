# Release History

## 0.1.0

First release containining stable features.

- One CZMQ context per external C port
- Create and destroy sockets
- Bind and connect operations
- zstr (single part, string oriented messages) send and receive operations
- Multipart send and receive operations
- Most auth operations (i.e. black and white lists, BASIC, and CURVE - may
  be incomplete for edge cases)
- Polling mechanism for pull messages into Erlang process mailboxes
- Partial support for socket options (edge cases not yet supported)
- Relatively complete test suite
- Benchmarking tools
- Cross platform build support including static or dynamic builds
- Integration with rebar builds

Thanks to Benoit Chesneau (benoitc) for driving this release forward!
