set -e

NUM_RUNS=1

echo "Number of test runs is set to $NUM_RUNS"

# needed if cargo was installed but the terminal has not been reinitialized yet
if [ -d "$HOME/.cargo/bin" ] && ! echo ":$PATH:" | grep ":$HOME/.cargo/bin:"; then
    echo "./cargo/bin is not in the path, adding it for you"
    export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "Running cargo check..."
cargo check --all-targets --all-features

echo "Formatting..."
cargo fmt --all

# Configure clippy lints

CLIPPY=
allow() {
    CLIPPY="$CLIPPY --allow=$1"
}
deny() {
    CLIPPY="$CLIPPY --deny=$1"
}

allow "clippy::too-many-arguments"
allow "clippy::significant-drop-in-scrutinee"
deny "warnings"
deny "bare_trait_objects"
deny "clippy::map_unwrap_or"
deny "ellipsis_inclusive_range_patterns"
deny "unconditional_recursion"

echo "Clippy checks: $CLIPPY"

cargo clippy --all-targets --tests -Z=unstable-options -- --deny=warnings $CLIPPY

# Run all the tests
counter=0
while [ "$counter" -lt "$NUM_RUNS" ]
do
    echo "---------------- Running tests ----------------"
    cargo test --all-features -- --test-threads=1
    ((counter += 1))
    printf "\n\n"
done
