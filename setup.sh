set -e
cd -- "$(dirname -- "$0")"
pwd

IS_HARD_ENABLED=false
while [ ! $# -eq 0 ]
do
    if [ "$1" = "--hard" ]; then
        IS_HARD_ENABLED=true
    fi
    shift
done

if [ -d "$HOME/.cargo/bin" ]; then
    echo 'rustup already installed'
else
    echo 'Installing rustup'
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
fi

if rustup --version; then
    echo 'rustup already in the path'
else
    echo "./cargo/bin is not in the path, adding it for you"
    export PATH="$HOME/.cargo/bin:$PATH"
fi

echo 'Checking for rustup updates'
rustup self update
rustc --version
cargo --version

echo "Setting nightly toolchain..."
rustup install nightly-2022-08-11
rustup override set nightly-2022-08-11

rustup component add rustfmt --toolchain nightly-2022-08-11
rustup component add clippy --toolchain nightly-2022-08-11
echo "Set nightly toolchain..."

if $IS_HARD_ENABLED; then
    echo "Hard flag is set! Cleaning caches..."
    if [ -d "./target" ]; then
        # Delete all subfolders
        find ./target -maxdepth 1 -mindepth 1 -type d -exec rm -rf {} \;
        # Delete remaining files
        find ./target -maxdepth 1 -mindepth 1 -exec rm {} \;
    fi
    if [ -d "../.cargo/target" ]; then
        # Delete all subfolders
        find d ../.cargo/target/ -maxdepth 1 -mindepth 1 -type d -exec rm -rf {} \;
        # Delete remaining files
        find ../.cargo/target/ -maxdepth 1 -mindepth 1 -exec rm {} \;
    fi
fi

if $IS_HARD_ENABLED; then
    echo "Hard flag is set! Updating cargo..."
    cargo update
fi

echo "Rust configured!"
