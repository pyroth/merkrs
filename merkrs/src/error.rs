use thiserror::Error;

/// Errors that can occur during Merkle tree operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The leaf set was empty.
    #[error("expected at least one leaf")]
    EmptyLeaves,

    /// An index exceeded the collection length.
    #[error("index {index} is out of bounds (len {len})")]
    IndexOutOfBounds {
        /// The requested index.
        index: usize,
        /// The actual length.
        len: usize,
    },

    /// A tree index does not correspond to a leaf node.
    #[error("index {0} is not a leaf node")]
    NotALeaf(usize),

    /// The root node (index 0) has no parent.
    #[error("root node has no parent")]
    RootHasNoParent,

    /// The root node (index 0) has no sibling.
    #[error("root node has no sibling")]
    RootHasNoSibling,

    /// The same leaf index appeared more than once.
    #[error("duplicate leaf index {0}")]
    DuplicateIndex(usize),

    /// A value was not found in the hash-lookup table.
    #[error("leaf not found in tree")]
    LeafNotFound,

    /// Internal consistency check failed.
    #[error("tree validation failed: computed root does not match")]
    InvalidTree,

    /// A stored value does not match its expected leaf hash.
    #[error("value at index {0} does not match its leaf hash")]
    ValueMismatch(usize),

    /// A generated proof did not verify against the root.
    #[error("unable to prove value at index {0}")]
    UnableToProve(usize),

    /// Proof-element count mismatch in a multi-proof.
    #[error("invalid multiproof: expected {expected} proof elements, got {got}")]
    InvalidMultiproof {
        /// Expected number of proof elements.
        expected: usize,
        /// Actual number of proof elements.
        got: usize,
    },

    /// The multi-proof invariant `leaves + proof == flags + 1` was violated.
    #[error("incompatible multiproof: leaves({leaves}) + proof({proof}) != flags({flags}) + 1")]
    IncompatibleMultiproof {
        /// Number of leaves in the multi-proof.
        leaves: usize,
        /// Number of proof elements.
        proof: usize,
        /// Number of proof flags.
        flags: usize,
    },

    /// The multi-proof processing stack underflowed.
    #[error("multiproof processing failed: {0}")]
    MultiproofUnderflow(&'static str),

    /// An unrecognised serialisation format string was encountered.
    #[error("unknown format: {0}")]
    UnknownFormat(String),

    /// The `leaf_encoding` field was empty when loading a standard tree.
    #[error("missing leaf encoding")]
    MissingLeafEncoding,

    /// A hex string could not be decoded.
    #[error("hex decode: {0}")]
    HexDecode(String),

    /// ABI encoding failed.
    #[error("ABI encode: {0}")]
    AbiEncode(String),

    /// A byte slice was not exactly 32 bytes.
    #[error("node must be exactly 32 bytes, got {0}")]
    InvalidNodeLength(usize),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
