#!/bin/sh

CORE_TOP=`pwd`
export CORE_TOP

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

LIBZMQ_DISTNAME=zeromq-4.0.3.tar.gz
LIBZMQ_SITE=http://download.zeromq.org
LIBZMQ_DIR=$STATICLIBS/libzmq

CZMQ_DISTNAME=czmq-2.0.3.tar.gz
CZMQ_SITE=http://download.zeromq.org/
CZMQ_DIR=$STATICLIBS/czmq

[ "$MACHINE" ] || MACHINE=`(uname -m) 2>/dev/null` || MACHINE="unknown"
[ "$RELEASE" ] || RELEASE=`(uname -r) 2>/dev/null` || RELEASE="unknown"
[ "$SYSTEM" ] || SYSTEM=`(uname -s) 2>/dev/null`  || SYSTEM="unknown"
[ "$BUILD" ] || VERSION=`(uname -v) 2>/dev/null` || VERSION="unknown"

# find arcg
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

    rm -rf $STATICLIBS/libsodium-0.4.5
    rm -rf $LIBSODIUM_DIR

    cd $STATICLIBS
    $GUNZIP -c $DISTDIR/$LIBSODIUM_DISTNAME | $TAR xf -

    cd $STATICLIBS/libsodium-0.4.5
    
    env LDFLAGS="$LDFLAGS" ./configure --prefix=$LIBSODIUM_DIR \
        --disable-debug \
        --disable-dependency-tracking \
        --disable-shared \
        --disable-ssp \
        --disable-pie \
        --disable-silent-rules

    make
    make install || exit 1
}

build_libzmq()
{
    fetch $LIBZMQ_DISTNAME $LIBZMQ_SITE
    echo "==> build libzmq"

    rm -rf $STATICLIBS/zeromq-4.0.3

    cd $STATICLIBS
    $GUNZIP -c $DISTDIR/$LIBZMQ_DISTNAME | $TAR xf -


    cd $STATICLIBS/zeromq-4.0.3

    env CFLAGS="$CFLAGS" \
        LDFLAGS="-lstdc++" \
        LIBS="-lstdc++ $LIBSODIUM_DIR/lib/libsodium.a" \
        CPPFLAGS="-Wno-long-long" \
        ./configure --prefix=$LIBZMQ_DIR \
        --disable-dependency-tracking \
        --enable-static \
        --disable-shared \
        --with-libsodium-include-dir=$LIBSODIUM_DIR/include \
        --with-libsodium-lib-dir=$LIBSODIUM_DIR/lib/libsodium.a \
        --disable-silent-rules
         
    make
    make install || exit 1

}

build_czmq()
{
    fetch $CZMQ_DISTNAME $CZMQ_SITE
    echo "==> build czmq"

    rm -rf $STATICLIBS/czmq-2.0.3

    cd $STATICLIBS
    $GUNZIP -c $DISTDIR/$CZMQ_DISTNAME | $TAR xf -

    echo $LIBZMQ_DIR
    cd $STATICLIBS/czmq-2.0.3

    
    env CFLAGS="-I$LIBSODIUM_DIR/include -I$LIBZMQ_DIR/include" \
        LDFLAGS="-lstdc++" \
        LIBS="$LIBSODIUM_DIR/lib/libsodium.a $LIBZMQ_DIR/lib/libzmq.a" \
        ./configure --prefix=$CZMQ_DIR \
        --disable-dependency-tracking \
        --enable-static \
        --disable-shared \
        --with-libsodium-include-dir=$LIBSODIUM_DIR/include \
        --with-libsodium-lib-dir=$LIBSODIUM_DIR/lib/libsodium.a \
        --with-libzmq-include-dir=$LIBZMQ_DIR/include \
        --with-libzmq-lib-dir=$LIBZMQ_DIR/lib/libzmq.a \
        --disable-silent-rules

    make
    make install  || exit 1
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

Report bugs at <https://github.com/refuge/couch_core>.
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
