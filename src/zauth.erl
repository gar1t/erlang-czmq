-module(zauth).

-export([new/1,
         allow/2,
         deny/2,
         configure_plain/3,
         configure_curve/3,
         set_verbose/2,
         destroy/1,
         test/1]).

new(_Context) -> xxx.

allow(_Auth, _Address) -> xxx.

deny(_Auth, _Address) -> xxx.

configure_plain(_Auth, _Domain, _File) -> xxx.

configure_curve(_Auth, _Domain, _Location) -> xxx.

set_verbose(_Auth, _Verbose) -> xxx.

destroy(_Auth) -> xxx.

test(_Verbose) -> xxx.
