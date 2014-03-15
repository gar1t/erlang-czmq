#!/bin/sh


if [ "x$CORE_TOP" = "x" ]; then
    CORE_TOP=`pwd`
    export CORE_TOP
fi

CURLBIN=`which curl`
if ! test -n "CURLBIN"; then
    display_error "Error: curl is required. Add it to 'PATH'"
    exit 1
fi

GUNZIP=`which gunzip`
UNZIP=`which unzip`
TAR=`which tar`
GNUMAKE=`which gmake 2>/dev/null || which make`



STATICLIBS=$CORE_TOP/.libs
DISTDIR=$CORE_TOP/.dists

LIBSODIUM_DISTNAME=libsodium-0.4.5.tar.gz
LIBSODIUM_SITE=https://download.libsodium.org/libsodium/releases/
LIBSODIUM_DIR=$STATICLIBS/libsodium

LIBZMQ_DISTNAME=zeromq-4.0.4.tar.gz
LIBZMQ_SITE=http://download.zeromq.org
LIBZMQ_DIR=$STATICLIBS/libzmq

CZMQ_DISTNAME=czmq-2.0.3.tar.gz
CZMQ_SITE=http://download.zeromq.org/
CZMQ_DIR=$STATICLIBS/czmq

[ "$MACHINE" ] || MACHINE=`(uname -m) 2>/dev/null` || MACHINE="unknown"
[ "$RELEASE" ] || RELEASE=`(uname -r) 2>/dev/null` || RELEASE="unknown"
[ "$SYSTEM" ] || SYSTEM=`(uname -s) 2>/dev/null`  || SYSTEM="unknown"
[ "$BUILD" ] || VERSION=`(uname -v) 2>/dev/null` || VERSION="unknown"

# find arch
PATCH=patch
case "$SYSTEM" in
    Linux)
        ARCH=`arch 2>/dev/null`
        ;;
    FreeBSD|OpenBSD|NetBSD)
        ARCH=`(uname -p) 2>/dev/null`
        ;;
    Darwin)
        ARCH=`(uname -p) 2>/dev/null`
        ;;
    Solaris)
        ARCH=`(uname -p) 2>/dev/null`
        PATCH=gpatch
        ;;
    *)
        ARCH="unknown"
        ;;
esac

CFLAGS="-g -O2 -Wall"
LDFLAGS="-lstdc++"

# TODO: add mirror & signature validation support
fetch()
{
    TARGET=$DISTDIR/$1
    if ! test -f $TARGET; then
        echo "==> Fetch $1 to $TARGET"
        $CURLBIN --progress-bar -L $2/$1 -o $TARGET
    fi
}

build_libsodium()
{
    fetch $LIBSODIUM_DISTNAME $LIBSODIUM_SITE
    echo "==> build libsodium"

    cd $STATICLIBS
    if ! test -f $STATICLIBS/libsodium-0.4.5; then
        $GUNZIP -c $DISTDIR/$LIBSODIUM_DISTNAME | $TAR xf -
    fi

    cd $STATICLIBS/libsodium-0.4.5
    if ! test -f config.status; then
        ./configure --prefix=$LIBSODIUM_DIR \
            --disable-debug \
            --disable-dependency-tracking \
            --disable-silent-rules
    fi
    make && make install || exit 1
}

build_libzmq()
{
    fetch $LIBZMQ_DISTNAME $LIBZMQ_SITE
    echo "==> build libzmq"

    cd $STATICLIBS
    if ! test -f $STATICLIBS/zeromq-4.0.4; then
        $GUNZIP -c $DISTDIR/$LIBZMQ_DISTNAME | $TAR xf -
    fi


    cd $STATICLIBS/zeromq-4.0.4
    if ! test -f config.status; then
	env CFLAGS="$CFLAGS -I$LIBSODIUM_DIR/include" \
	    LDFLAGS="-L$LIBSODIUM_DIR/lib -lstdc++ " \
	    CPPFLAGS="-Wno-long-long" \
	    ./configure --prefix=$LIBZMQ_DIR \
	    --disable-dependency-tracking \
	    --enable-static \
	    --with-libsodium=$LIBSODIUM_DIR \
	    --disable-silent-rules
    fi
    make && make install || exit 1
}

build_czmq()
{
    fetch $CZMQ_DISTNAME $CZMQ_SITE
    echo "==> build czmq"

    cd $STATICLIBS
    if ! test -f $STATICLIBS/czmq-2.0.3; then
        $GUNZIP -c $DISTDIR/$CZMQ_DISTNAME | $TAR xf -
    fi

    echo $LIBZMQ_DIR
    cd $STATICLIBS/czmq-2.0.3

    $PATCH -p0 -i $CORE_TOP/patch-zauth_c || echo "skipping patch"
    $PATCH -p0 -i $CORE_TOP/patch-zsockopt_c || echo "skipping patch"

    if ! test -f config.status; then
    env CFLAGS="-I$LIBSODIUM_DIR/include -I$LIBZMQ_DIR/include" \
        LDFLAGS="-lstdc++ -lpthread -L$LIBSODIUM_DIR/lib -L$LIBZMQ_DIR/lib -lstdc++" \
        ./configure --prefix=$CZMQ_DIR \
        --disable-dependency-tracking \
        --enable-static \
        --with-libsodium=$LIBSODIUM_DIR \
        --with-libzmq=$LIBZMQ_DIR \
        --disable-silent-rules
    fi
    make && make install || exit 1
}

do_build()
{
    mkdir -p $DISTDIR
    mkdir -p $STATICLIBS

    if [ ! -f $LIBSODIUM_DIR/lib/libsodium.a ]; then
        build_libsodium
    fi

    if [ ! -f $LIBZMQ_DIR/lib/libzmq.a ]; then
        build_libzmq
    fi

    if [ ! -f $CZMQ_DIR/lib/libczmq.a ]; then
        build_czmq
    fi
}

clean()
{
    rm -rf $STATICLIBS
}

usage()
{
    cat << EOF
Usage: $basename [command] [OPTIONS]

The $basename command compile czmq statically

Commands:

    all:        build static libs
    clean:      clean static libs
    -?:         display usage

Report bugs at <https://github.com/gar1t/erlang-czmq>.
EOF
}

if [ "x$1" = "x" ]; then
    do_build
	exit 0
fi

case "$1" in
    all)
        shift 1
        do_build
        ;;
    clean)
        shift 1
        clean
        ;;
    help|--help|-h|-?)
        usage
        exit 0
        ;;
    *)
        echo $basename: ERROR Unknown command $arg 1>&2
        echo 1>&2
        usage 1>&2
        echo "### $basename: Exitting." 1>&2
        exit 1;
        ;;
esac

exit 0
