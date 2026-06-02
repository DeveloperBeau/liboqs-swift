#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION=$(cat "$REPO_ROOT/LIBOQS_VERSION")
DEST="$REPO_ROOT/Sources/Cliboqs"

echo "Vendoring liboqs $VERSION..."

if [ -d "$DEST/src" ]; then
    rm -rf "$DEST/src"
fi
# Preserve oqsconfig.h (manually maintained) across re-vendoring
if [ -f "$DEST/include/oqs/oqsconfig.h" ]; then
    cp "$DEST/include/oqs/oqsconfig.h" "$DEST/include/oqsconfig.h.bak"
fi
if [ -d "$DEST/include/oqs" ]; then
    rm -rf "$DEST/include/oqs"
fi

TMPDIR=$(mktemp -d)
TARBALL="$TMPDIR/liboqs-$VERSION.tar.gz"
curl -sL "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$VERSION.tar.gz" -o "$TARBALL"
tar -xzf "$TARBALL" -C "$TMPDIR"
LIBOQS_SRC="$TMPDIR/liboqs-$VERSION/src"

mkdir -p "$DEST/src"
cp -R "$LIBOQS_SRC/common" "$DEST/src/"
cp -R "$LIBOQS_SRC/kem" "$DEST/src/"
cp -R "$LIBOQS_SRC/sig" "$DEST/src/"
cp -R "$LIBOQS_SRC/sig_stfl" "$DEST/src/"

mkdir -p "$DEST/include/oqs"

# Core public headers
cp "$LIBOQS_SRC/oqs.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/common.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/rand/rand.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/rand/rand_nist.h" "$DEST/include/oqs/" 2>/dev/null || true
cp "$LIBOQS_SRC/kem/kem.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/sig/sig.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/sig_stfl/sig_stfl.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/sig_stfl/xmss/sig_stfl_xmss.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/sig_stfl/lms/sig_stfl_lms.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/aes/aes_ops.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/aes/aes.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha2/sha2_ops.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha2/sha2.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha3/sha3_ops.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha3/sha3.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha3/sha3x4_ops.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha3/sha3x4.h" "$DEST/include/oqs/"

# Per-algorithm public headers (kem_*.h, sig_*.h at algorithm directory level)
for dir in "$LIBOQS_SRC"/kem/*/; do
    for h in "$dir"kem_*.h; do
        [ -f "$h" ] && cp "$h" "$DEST/include/oqs/"
    done
done
for dir in "$LIBOQS_SRC"/sig/*/; do
    for h in "$dir"sig_*.h; do
        [ -f "$h" ] && cp "$h" "$DEST/include/oqs/"
    done
done

# Fetch upstream KAT hash manifests for cross-checking (best-effort, reference-only).
# Kept OUTSIDE Tests/OQSTests/Vectors so the test bundle stays small.
KAT_DIR="$REPO_ROOT/Tests/OQSTests/UpstreamKATs"
mkdir -p "$KAT_DIR"
if [ -d "$TMPDIR/liboqs-$VERSION/tests/KATs" ]; then
    cp -R "$TMPDIR/liboqs-$VERSION/tests/KATs" "$KAT_DIR/" 2>/dev/null || true
fi

rm -rf "$TMPDIR"

# Restore oqsconfig.h
if [ -f "$DEST/include/oqsconfig.h.bak" ]; then
    cp "$DEST/include/oqsconfig.h.bak" "$DEST/include/oqs/oqsconfig.h"
    rm "$DEST/include/oqsconfig.h.bak"
fi

echo "Done. Vendored liboqs $VERSION into $DEST"
