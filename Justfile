binary := "target/debug/depx"

# Default task: run all tests
default: test

# Build the project
build:
    cargo build

# Run all tests
test: test-cargo test-npm
    @echo "All tests passed!"

# Run Cargo duplicate tests
test-cargo: build
    @echo "Running Cargo duplicate tests..."
    @CLICOLOR_FORCE=1 {{ binary }} duplicates test_suite/cargo_duplicates --verbose
    @{{ binary }} duplicates test_suite/cargo_duplicates --verbose > cargo_output.txt
    @grep -q "serde (2 versions)" cargo_output.txt
    @grep -q "v1.0.152 (2 transitive)" cargo_output.txt
    @grep -q "v1.0.150 (4 transitive)" cargo_output.txt
    @echo "Cargo tests passed!"

# Run npm analysis and duplicate tests
test-npm: build
    @echo "Running npm analysis tests..."
    @CLICOLOR_FORCE=1 {{ binary }} analyze test_suite/npm_duplicates --unused
    @{{ binary }} analyze test_suite/npm_duplicates --unused > npm_output.txt
    @grep -q "Potentially Unused Dependencies" npm_output.txt
    @echo "\nRunning npm duplicate tests..."
    @CLICOLOR_FORCE=1 {{ binary }} duplicates test_suite/npm_duplicates --verbose
    @{{ binary }} duplicates test_suite/npm_duplicates --verbose > npm_output.txt
    @grep -q "lodash (2 versions)" npm_output.txt
    @grep -q "v4.17.21 (2 transitive)" npm_output.txt
    @grep -q "v4.17.20 (4 transitive)" npm_output.txt
    @echo "NPM tests passed!"

# Format all files under src/
fmt:
    cargo fmt --all

# Clean build artifacts
clean:
    rm -f cargo_output.txt npm_output.txt
    cargo clean
