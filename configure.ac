AC_INIT(erlang-czmq, version-0.0)

AC_PROG_CC
AC_ERLANG_CHECK_LIB([erl_interface])

AC_ARG_ENABLE([static],
              AC_HELP_STRING([--enable-static=@<:@yes/no@:>@],
                             [enable static build [default=yes]]),
              [],
              [enable_static=yes])
AC_MSG_NOTICE([enabling static build... $enable_static])
AC_SUBST(enable_static)

#AC_CHECK_HEADERS([ev.h], [], [AC_MSG_ERROR("ev.h not found")])
AC_CHECK_LIB([ev], [ev_run], [
        LIBS="-lev ${LIBS}"
        AC_DEFINE([HAVE_LIBEV], [1], [ev_run in -lev])
    ], [
        AC_MSG_ERROR("libev not found")
    ])

AC_OUTPUT(Makefile)
AC_OUTPUT(c_src/Makefile)
