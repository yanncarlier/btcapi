1. Set Up Rust (if not already installed)
If you don't have Rust installed, install it using rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the prompts to install. After installation, run:

```bash
source $HOME/.cargo/env
```

On Windows: Download and run the installer from [rustup.rs](https://rustup.rs/). Follow the installation instructions.

```bash
rustc --version
cargo --version
```

You should see the versions of rustc (Rust compiler) and cargo (Rust package manager).



3. Compile the Code

To compile the Rust code, run the following command in the project directory (bitcoin_address_generator):

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
cargo run
```

This command compiles (if necessary) and executes the program.

For release mode, use:

```bash
cargo run --release
```
