#!/bin/bash
#
# build-deb.sh -- build barnyard2 and produce a .deb for Debian 13 (trixie).
#
# Two modes:
#
#   ./build-deb.sh              build natively (must be run on Debian 13)
#   ./build-deb.sh --docker     build inside a debian:13 container
#
# The finished package is written to ./dist/.
#
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SRC_DIR}/dist"

BUILD_DEPS=(
    build-essential
    debhelper
    dh-autoreconf
    devscripts
    fakeroot
    autoconf
    automake
    libtool
    pkgconf
    libpcap-dev
    libdumbnet-dev
    default-libmysqlclient-dev
    zlib1g-dev
    libssl-dev
)

DOCKER_IMAGE="debian:13"

usage() {
    cat <<EOF
Usage: $0 [--docker] [--image IMAGE] [--install-deps]

  --docker         Build inside a $DOCKER_IMAGE container instead of on this
                   machine. Use this when the host is not Debian 13.
  --image IMAGE    Container image to build in (implies --docker).
  --install-deps   Install the build dependencies with apt before building.
                   Requires root; implied by --docker.
  -h, --help       Show this message.

Output: $OUT_DIR/barnyard2_*.deb
EOF
}

USE_DOCKER=0
INSTALL_DEPS=0

while [ $# -gt 0 ]; do
    case "$1" in
        --docker)       USE_DOCKER=1; shift ;;
        --image)        DOCKER_IMAGE="$2"; USE_DOCKER=1; shift 2 ;;
        --install-deps) INSTALL_DEPS=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------- docker mode

if [ "$USE_DOCKER" -eq 1 ]; then
    if ! command -v docker >/dev/null; then
        echo "error: docker is not installed" >&2
        exit 1
    fi

    echo ">> Building in $DOCKER_IMAGE"
    mkdir -p "$OUT_DIR"

    # The source is copied into the container so the build never writes into
    # the working tree, and so a dirty tree cannot leak into the package.
    docker run --rm \
        -v "${SRC_DIR}:/src:ro" \
        -v "${OUT_DIR}:/out" \
        -e DEBIAN_FRONTEND=noninteractive \
        "$DOCKER_IMAGE" \
        bash -euc '
            cp -a /src /build
            rm -rf /build/dist /build/.git
            cd /build
            ./build-deb.sh --install-deps
            cp /build/../barnyard2_*.deb /out/ 2>/dev/null || cp /build/dist/*.deb /out/
            chmod 0644 /out/*.deb
        '

    echo
    echo ">> Package(s) in $OUT_DIR:"
    ls -la "$OUT_DIR"/*.deb
    exit 0
fi

# ---------------------------------------------------------------- native mode

if [ -r /etc/os-release ]; then
    . /etc/os-release
    if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
        echo "warning: this is ${PRETTY_NAME:-an unknown system}, not Debian 13." >&2
        echo "         The resulting .deb will be linked against this system's" >&2
        echo "         libraries. Use --docker to build a real trixie package." >&2
        echo >&2
    fi
fi

if [ "$INSTALL_DEPS" -eq 1 ]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo "error: --install-deps needs root" >&2
        exit 1
    fi
    echo ">> Installing build dependencies"
    apt-get update -qq
    apt-get install -y --no-install-recommends "${BUILD_DEPS[@]}"
fi

missing=()
for pkg in "${BUILD_DEPS[@]}"; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "^install ok installed$" || missing+=("$pkg")
done

if [ "${#missing[@]}" -gt 0 ]; then
    echo "error: missing build dependencies: ${missing[*]}" >&2
    echo "       run: sudo apt-get install ${missing[*]}" >&2
    echo "       or:  sudo $0 --install-deps" >&2
    exit 1
fi

cd "$SRC_DIR"

echo ">> Cleaning previous build artefacts"
rm -rf dist
[ -f Makefile ] && make distclean >/dev/null 2>&1 || true
rm -rf autom4te.cache

echo ">> Building package"
# -us -uc: unsigned. -b: binary only, so no orig tarball is needed.
dpkg-buildpackage -us -uc -b

mkdir -p "$OUT_DIR"
mv ../barnyard2_*.deb "$OUT_DIR/" 2>/dev/null || true
mv ../barnyard2_*.buildinfo ../barnyard2_*.changes "$OUT_DIR/" 2>/dev/null || true

echo
echo ">> Done. Package(s) in $OUT_DIR:"
ls -la "$OUT_DIR"/*.deb
echo
echo "Install with:  sudo apt install $OUT_DIR/barnyard2_*.deb"
