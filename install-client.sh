#!/bin/sh
set -eu

repository="${HETERONETWORK_REPOSITORY:-IPA-CyberLab/IPA-RS-HeteroNetwork}"
version="${HETERONETWORK_VERSION:-latest}"
platform=""
install_dir=""
download_dir=""
launch_after_install=1

usage() {
    cat <<'EOF'
Install the latest HeteroNetwork desktop client.

Usage: install-client.sh [options]

Options:
  --version TAG          Install a specific release tag (default: newest release).
  --platform PLATFORM    Override detection: macos-arm64, macos-x64, windows-x64.
  --install-dir DIR      Override the per-user installation directory.
  --download-only DIR    Verify and save the release archive without installing it.
  --no-launch            Do not start the client after installation.
  --self-test            Run platform-selection tests without downloading anything.
  -h, --help             Show this help.

Environment:
  HETERONETWORK_VERSION      Same as --version.
  HETERONETWORK_REPOSITORY   GitHub owner/repository used for downloads.
EOF
}

fail() {
    printf 'HeteroNetwork installer: %s\n' "$*" >&2
    exit 1
}

detect_platform() {
    detected_os=$1
    detected_arch=$2
    case "$detected_os:$detected_arch" in
        Darwin:arm64|Darwin:aarch64)
            printf '%s\n' macos-arm64
            ;;
        Darwin:x86_64|Darwin:amd64)
            printf '%s\n' macos-x64
            ;;
        MINGW*:x86_64|MINGW*:amd64|MSYS*:x86_64|MSYS*:amd64|CYGWIN*:x86_64|CYGWIN*:amd64)
            printf '%s\n' windows-x64
            ;;
        *)
            return 1
            ;;
    esac
}

asset_for_platform() {
    case "$1" in
        macos-arm64)
            printf '%s\n' heteronetwork-client-macos-arm64.zip
            ;;
        macos-x64)
            printf '%s\n' heteronetwork-client-macos-x64.zip
            ;;
        windows-x64)
            printf '%s\n' heteronetwork-client-windows-x64.zip
            ;;
        *)
            return 1
            ;;
    esac
}

latest_release_for_asset() {
    wanted_asset=$1
    awk -v wanted_asset="$wanted_asset" '
        function json_string_value(line) {
            sub(/^[^:]*:[[:space:]]*"/, "", line)
            sub(/".*$/, "", line)
            return line
        }

        /^    "tag_name":[[:space:]]*"/ {
            release_tag = json_string_value($0)
            release_published_at = ""
        }
        /^    "published_at":[[:space:]]*"/ {
            release_published_at = json_string_value($0)
        }
        /^        "name":[[:space:]]*"/ {
            asset_name = json_string_value($0)
            if (asset_name == wanted_asset \
                    && release_tag != "" \
                    && release_published_at > newest_published_at) {
                newest_published_at = release_published_at
                newest_tag = release_tag
            }
        }
        END {
            print newest_tag
        }
    '
}

run_self_test() {
    test "$(detect_platform Darwin arm64)" = macos-arm64
    test "$(detect_platform Darwin x86_64)" = macos-x64
    test "$(detect_platform MINGW64_NT-10.0 x86_64)" = windows-x64
    test "$(detect_platform MSYS_NT-10.0 amd64)" = windows-x64
    if detect_platform Linux x86_64 >/dev/null 2>&1; then
        fail 'self-test accepted an unsupported Linux platform'
    fi
    test "$(asset_for_platform macos-arm64)" = heteronetwork-client-macos-arm64.zip
    test "$(asset_for_platform macos-x64)" = heteronetwork-client-macos-x64.zip
    test "$(asset_for_platform windows-x64)" = heteronetwork-client-windows-x64.zip
    if asset_for_platform windows-arm64 >/dev/null 2>&1; then
        fail 'self-test accepted an unsupported release platform'
    fi
    selected_release=$(
        latest_release_for_asset heteronetwork-client-macos-arm64.zip <<'EOF'
[
  {
    "tag_name": "v0.1.15-dev.9",
    "published_at": "2026-09-17T14:46:58Z",
    "assets": []
  },
  {
    "tag_name": "v0.1.15-dev.12",
    "published_at": "2026-09-17T16:00:00Z",
    "assets": [
      {
        "name": "heteronetwork-client-windows-x64.zip"
      }
    ]
  },
  {
    "tag_name": "v0.1.15-dev.11",
    "published_at": "2026-09-17T15:06:49Z",
    "assets": [
      {
        "name": "heteronetwork-client-macos-arm64.zip"
      }
    ]
  },
  {
    "tag_name": "v0.1.15-dev.10",
    "published_at": "2026-09-17T14:52:53Z",
    "assets": [
      {
        "name": "heteronetwork-client-macos-arm64.zip"
      }
    ]
  }
]
EOF
    )
    test "$selected_release" = v0.1.15-dev.11
    printf '%s\n' 'HeteroNetwork installer self-test passed.'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || fail '--version requires a value'
            version=$2
            shift 2
            ;;
        --platform)
            [ "$#" -ge 2 ] || fail '--platform requires a value'
            platform=$2
            shift 2
            ;;
        --install-dir)
            [ "$#" -ge 2 ] || fail '--install-dir requires a value'
            install_dir=$2
            shift 2
            ;;
        --download-only)
            [ "$#" -ge 2 ] || fail '--download-only requires a directory'
            download_dir=$2
            shift 2
            ;;
        --no-launch)
            launch_after_install=0
            shift
            ;;
        --self-test)
            run_self_test
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

case "$repository" in
    ''|/*|*..*|*//*|*/*/*|*[!A-Za-z0-9._/-]*)
        fail 'HETERONETWORK_REPOSITORY must be a GitHub owner/repository name'
        ;;
esac

command -v curl >/dev/null 2>&1 || fail 'curl is required'

if [ -z "$platform" ]; then
    detected_os=$(uname -s 2>/dev/null || true)
    detected_arch=$(uname -m 2>/dev/null || true)
    platform=$(detect_platform "$detected_os" "$detected_arch") \
        || fail "unsupported platform: ${detected_os:-unknown}/${detected_arch:-unknown}"
fi
asset=$(asset_for_platform "$platform") \
    || fail "unsupported release platform: $platform"

if [ "$version" = latest ]; then
    release_json=$(curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 60 --retry 3 --retry-all-errors \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        "https://api.github.com/repos/$repository/releases?per_page=100")
    version=$(printf '%s\n' "$release_json" | latest_release_for_asset "$asset")
    [ -n "$version" ] \
        || fail "GitHub did not return a published release containing $asset"
fi
case "$version" in
    ''|*[!A-Za-z0-9._-]*)
        fail 'release tag contains unsupported characters'
        ;;
esac

temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-client.XXXXXX") \
    || fail 'unable to create a temporary directory'
staged_path=""
cleanup() {
    if [ -n "$staged_path" ]; then
        rm -rf "$staged_path"
    fi
    rm -rf "$temporary_dir"
}
trap cleanup EXIT HUP INT TERM

archive="$temporary_dir/$asset"
checksum="$temporary_dir/$asset.sha256"
release_url="https://github.com/$repository/releases/download/$version"

curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 600 --retry 3 --retry-all-errors \
    --output "$archive" "$release_url/$asset"
curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 60 --retry 3 --retry-all-errors \
    --output "$checksum" "$release_url/$asset.sha256"

set -f
# The checksum file is generated by the release workflow as exactly two fields.
set -- $(cat "$checksum")
set +f
[ "$#" -eq 2 ] || fail "invalid checksum file for $asset"
expected_checksum=$1
checksum_asset=$2
case "$expected_checksum" in
    *[!0-9a-f]*|'')
        fail "invalid SHA-256 value for $asset"
        ;;
esac
[ "${#expected_checksum}" -eq 64 ] || fail "invalid SHA-256 length for $asset"
[ "$checksum_asset" = "$asset" ] || fail "checksum file names a different asset"

if command -v shasum >/dev/null 2>&1; then
    actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
    actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
else
    fail 'shasum or sha256sum is required'
fi
[ "$actual_checksum" = "$expected_checksum" ] || fail "SHA-256 mismatch for $asset"

if [ -n "$download_dir" ]; then
    mkdir -p "$download_dir"
    cp "$archive" "$download_dir/$asset"
    cp "$checksum" "$download_dir/$asset.sha256"
    printf 'Downloaded and verified %s (%s) to %s\n' "$asset" "$version" "$download_dir"
    exit 0
fi

case "$platform" in
    macos-*)
        command -v ditto >/dev/null 2>&1 || fail 'ditto is required on macOS'
        extracted="$temporary_dir/extracted"
        mkdir "$extracted"
        ditto -x -k "$archive" "$extracted"
        source_app="$extracted/HeteroNetwork.app"
        [ ! -L "$source_app" ] || fail 'macOS archive contains a linked app bundle'
        [ -d "$source_app/Contents" ] || fail 'macOS archive does not contain HeteroNetwork.app'
        [ ! -L "$source_app/Contents/MacOS/HeteroNetwork" ] \
            || fail 'macOS archive contains a linked client executable'
        [ -f "$source_app/Contents/MacOS/HeteroNetwork" ] \
            || fail 'macOS archive does not contain the client executable'
        if ! codesign --verify --deep --strict "$source_app" >/dev/null 2>&1; then
            printf '%s\n' \
                'Warning: this development build is unsigned; macOS will not start its VPN Network Extension.' >&2
        fi

        if [ -z "$install_dir" ]; then
            install_dir="$HOME/Applications"
        fi
        mkdir -p "$install_dir"
        target_app="$install_dir/HeteroNetwork.app"
        [ ! -L "$target_app" ] || fail 'refusing to replace a linked macOS app bundle'
        staged_path="$install_dir/.HeteroNetwork.app.new.$$"
        backup_app="$install_dir/.HeteroNetwork.app.old.$$"
        rm -rf "$staged_path" "$backup_app"
        ditto "$source_app" "$staged_path"
        if [ -e "$target_app" ]; then
            mv "$target_app" "$backup_app"
        fi
        if ! mv "$staged_path" "$target_app"; then
            if [ -e "$backup_app" ]; then
                mv "$backup_app" "$target_app"
            fi
            fail 'unable to activate the macOS client'
        fi
        staged_path=""
        rm -rf "$backup_app"
        printf 'Installed HeteroNetwork %s at %s\n' "$version" "$target_app"
        if [ "$launch_after_install" -eq 1 ]; then
            open "$target_app"
        fi
        ;;
    windows-x64)
        command -v powershell.exe >/dev/null 2>&1 \
            || fail 'Windows installation requires Git Bash and powershell.exe'
        command -v cygpath >/dev/null 2>&1 \
            || fail 'Windows installation requires cygpath from Git Bash'
        archive_windows=$(cygpath -w "$archive")
        if [ -z "$install_dir" ]; then
            install_dir=$(powershell.exe -NoLogo -NoProfile -NonInteractive -Command \
                '[Environment]::GetFolderPath("LocalApplicationData") + "\Programs\HeteroNetwork"' \
                | tr -d '\r')
        fi
        [ -n "$install_dir" ] || fail 'unable to determine the Windows installation directory'
        HETERONETWORK_ARCHIVE_PATH="$archive_windows" \
        HETERONETWORK_INSTALL_PATH="$install_dir" \
        HETERONETWORK_LAUNCH="$launch_after_install" \
            powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command '
                $ErrorActionPreference = "Stop"
                $archive = $env:HETERONETWORK_ARCHIVE_PATH
                $target = $env:HETERONETWORK_INSTALL_PATH
                $parent = Split-Path -Parent $target
                $name = Split-Path -Leaf $target
                $stage = Join-Path $parent ".$name.new.$PID"
                $backup = Join-Path $parent ".$name.old.$PID"
                New-Item -ItemType Directory -Force -Path $parent | Out-Null
                if (Get-Process -Name HeteroNetwork -ErrorAction SilentlyContinue) {
                    throw "Exit HeteroNetwork before installing an update."
                }
                Remove-Item -LiteralPath $stage, $backup -Recurse -Force -ErrorAction SilentlyContinue
                try {
                    Expand-Archive -LiteralPath $archive -DestinationPath $stage
                    $executable = Join-Path $stage "HeteroNetwork.exe"
                    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
                        throw "The Windows archive does not contain HeteroNetwork.exe."
                    }
                    if (Test-Path -LiteralPath $target) {
                        Move-Item -LiteralPath $target -Destination $backup
                    }
                    try {
                        Move-Item -LiteralPath $stage -Destination $target
                    } catch {
                        if (Test-Path -LiteralPath $backup) {
                            Move-Item -LiteralPath $backup -Destination $target
                        }
                        throw
                    }
                    Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue
                    $executable = Join-Path $target "HeteroNetwork.exe"
                    $programs = [Environment]::GetFolderPath("Programs")
                    if ($programs) {
                        $shortcutPath = Join-Path $programs "HeteroNetwork.lnk"
                        $shell = New-Object -ComObject WScript.Shell
                        $shortcut = $shell.CreateShortcut($shortcutPath)
                        $shortcut.TargetPath = $executable
                        $shortcut.WorkingDirectory = $target
                        $shortcut.Save()
                    }
                    if ($env:HETERONETWORK_LAUNCH -eq "1") {
                        Start-Process -FilePath $executable
                    }
                } finally {
                    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
                }
            '
        printf 'Installed HeteroNetwork %s at %s\n' "$version" "$install_dir"
        ;;
esac
