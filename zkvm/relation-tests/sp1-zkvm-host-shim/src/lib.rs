//! Host-target stand-in for the `sp1_zkvm` items the SP1 ML-DSA-65 guest programs use.
//!
//! `mldsa65-relation-tests` compiles the guest programs' own sources for the host target. The
//! programs touch exactly three `sp1_zkvm` items, mirrored here from sp1-lib 6.3.1 (`src/io.rs`)
//! and sp1-zkvm 6.3.1 (`src/lib.rs`):
//!
//! - `entrypoint!(main)` registers `main` as the program entry. Here it only type-checks the path;
//!   the harness calls `main` directly.
//! - `io::read::<T>()` bincode-decodes the next prover-supplied stdin buffer. In the zkVM an absent
//!   or undecodable buffer halts the program with exit code 3 ("invalid hint"); here it panics,
//!   which the harness records as a rejection.
//! - `io::commit_slice(buf)` appends raw bytes to the public-values stream.
//!
//! Nothing here, and nothing in the zkVM, constrains what stdin carries: sp1-lib documents the
//! input stream as prover-controlled.

use std::cell::RefCell;

thread_local! {
    static STDIN: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    static PUBLIC_VALUES: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

pub mod io {
    use serde::de::DeserializeOwned;

    /// Mirrors `sp1_lib::io::read`: the next stdin buffer, decoded with bincode 1 defaults.
    pub fn read<T: DeserializeOwned>() -> T {
        let buffer = super::STDIN.with(|stdin| {
            let mut stdin = stdin.borrow_mut();
            if stdin.is_empty() {
                None
            } else {
                Some(stdin.remove(0))
            }
        });
        let Some(buffer) = buffer else {
            panic!("invalid hint: empty input stream (the zkVM halts with exit code 3)");
        };
        match bincode::deserialize(&buffer) {
            Ok(value) => value,
            Err(error) => {
                panic!("invalid hint: undecodable input (the zkVM halts with exit code 3): {error}")
            }
        }
    }

    /// Mirrors `sp1_lib::io::commit_slice`: raw bytes appended to the public-values stream.
    pub fn commit_slice(buf: &[u8]) {
        super::PUBLIC_VALUES
            .with(|public_values| public_values.borrow_mut().extend_from_slice(buf));
    }
}

/// Harness controls. Not part of the `sp1_zkvm` surface a guest program can reach.
pub mod harness {
    /// Replaces this thread's stdin buffers and clears its public-values stream.
    pub fn begin(stdin: Vec<Vec<u8>>) {
        super::STDIN.with(|queue| *queue.borrow_mut() = stdin);
        super::PUBLIC_VALUES.with(|public_values| public_values.borrow_mut().clear());
    }

    /// Takes the public values committed since [`begin`].
    pub fn take_public_values() -> Vec<u8> {
        super::PUBLIC_VALUES.with(|public_values| std::mem::take(&mut *public_values.borrow_mut()))
    }
}

/// Mirrors `sp1_zkvm::entrypoint!` for a host build: the path must name a `fn()`.
#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        const _: fn() = $path;
    };
}
