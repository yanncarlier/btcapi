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




```bash
cd bin/
```
Usage: ./generate_mnemonic <wordlist_path> <number_of_words>
```bash
./generate_mnemonic bip-0039/english.txt 12 
```
Usage: ./generate_addresses <mnemonic_phrase> <derivation_path> [passphrase]
```bash
./generate_addresses "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" "m/44'/0'/0'/0" ""
```
Usage: ./blockstream_balance_loop <file_name>
```bash
./blockstream_balance_loop addresses.txt
```

Vibe coding with grok, this is just a fun exercise.
The odds of finding an address with some bitcoins in it per cycle are approximately 2.94×10−312.94 \times 10^{-31}2.94 \times 10^{-31}
 to 1, assuming there are about 100 million seeds in use. This probability is extremely low, reflecting the vastness of the seed space and the security of Bitcoin’s design. Alternatively, as a ratio, the odds are 1 to 3.4×10303.4 \times 10^{30}3.4 \times 10^{30}
, but the probability 2.94×10−312.94 \times 10^{-31}2.94 \times 10^{-31}
 is a clear, concise response to the query.

```bash
./generate_mnemonic bip-0039/english.txt 12 | tee mnemonic.txt | xargs -I {} ./generate_addresses "{}" "m/44'/0'/0'/0" "" | grep address | cut -d ':' -f 2 > addresses.txt && ./blockstream_balance_loop addresses.txt
```

```bash
while true; do
    if ./generate_mnemonic bip-0039/english.txt 12 | tee mnemonic.txt | xargs -I {} ./generate_addresses "{}" "m/44'/0'/0'/0" "" | grep address | cut -d ':' -f 2 > addresses.txt && ./blockstream_balance_loop addresses.txt | tee /dev/tty | grep -q -v "Balance: 0 satoshis"; then
        break
    fi
done
```



```bash
while IFS= read -r line || [ -n "$line" ]; do     ./brain_wallet "$line"; done < quotes.txt | grep Address | cut -d ':' -f 2 > addresses.txt && ./blockstream_balance_loop addresses.txt
```









