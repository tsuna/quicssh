#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    echo "Usage: $0 [--deb|--pkg|--all]"
    echo ""
    echo "Options:"
    echo "  --deb    Build Debian package (.deb)"
    echo "  --pkg    Build Arch Linux package (.pkg.tar.zst)"
    echo "  --all    Build all packages"
    echo ""
    exit 1
}

build_deb() {
    echo "=== Building Debian package ==="
    
    docker run --rm \
        -v "$PROJECT_ROOT:/build" \
        -w /build \
        golang:1.25-trixie \
        bash -c "
            set -e
            apt-get update
            apt-get install -y dpkg-dev debhelper-compat
            
            # Link packaging/debian to debian (dpkg-buildpackage expects it at root)
            ln -sf packaging/debian debian
            
            # Build the package (-d skips build dependency check since Go is pre-installed)
            dpkg-buildpackage -us -uc -b -d
            
            # Move output to dist/
            mkdir -p dist
            mv ../*.deb dist/
            mv ../*.buildinfo dist/ 2>/dev/null || true
            mv ../*.changes dist/ 2>/dev/null || true
            
            # Clean up symlink
            rm debian
            
            echo ''
            echo 'Build completed successfully!'
            echo 'Package files:'
            ls -la dist/*.deb
        "
}

build_pkg() {
    echo "=== Building Arch Linux package ==="
    
    docker run --rm \
        -v "$PROJECT_ROOT:/build" \
        -w /build \
        archlinux:base-devel \
        bash -c "
            set -e
            
            # Update and install Go
            pacman -Sy --noconfirm go git
            
            # Create non-root user (makepkg refuses to run as root)
            useradd -m builder
            chown -R builder:builder /build
            
            # Build in packaging/arch directory, output to dist/
            su builder -c '
                set -e
                cd packaging/arch

                # Build the package with artifacts in subdirectory
                # BUILDDIR: where src/ and pkg/ are created
                # PKGDEST: where .pkg.tar.zst files go
                BUILDDIR=/build/packaging/arch/build \
                PKGDEST=/build/dist \
                makepkg -sf --noconfirm

                # Clean up build artifacts
                rm -rf build
            '
            
            echo ''
            echo 'Build completed successfully!'
            echo 'Package files:'
            ls -la dist/*.pkg.tar.zst
        "
}

# Parse arguments
if [[ $# -eq 0 ]]; then
    usage
fi

BUILD_DEB=false
BUILD_PKG=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --deb)
            BUILD_DEB=true
            shift
            ;;
        --pkg)
            BUILD_PKG=true
            shift
            ;;
        --all)
            BUILD_DEB=true
            BUILD_PKG=true
            shift
            ;;
        *)
            usage
            ;;
    esac
done

# Run builds
if $BUILD_DEB; then
    build_deb
fi

if $BUILD_PKG; then
    build_pkg
fi

echo ""
echo "=== All requested builds completed ==="
ls -la "$PROJECT_ROOT/dist/"

