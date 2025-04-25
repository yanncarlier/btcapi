Compile the Code

To compile the Rust code, run the following command in the project directory (generate_mnemonic):

```bash
cargo build
```

- This command downloads the dependencies specified in Cargo.toml, compiles the code, and generates an executable.
- If there are any compilation errors (e.g., missing dependencies or syntax issues), they will be displayed in the terminal. Ensure your Cargo.toml and main.rs match the provided code exactly.

To compile in release mode (optimized, smaller binary):

```bash
cargo build --release
```

4. Run the Code

To run the compiled program, use:

```bash
cargo run -- 12
```

This command compiles (if necessary) and executes the program.

For release mode, use:

```bash
cargo run --release -- 12
```

Compile and run the program with a command-line argument specifying the number of words:

- Replace 12 with 15, 18, 21, or 24 as desired.
