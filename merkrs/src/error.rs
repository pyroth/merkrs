use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeError {
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Invariant violation: {0}")]
    Invariant(String),

    #[error("Index is not a leaf")]
    NotALeaf,

    #[error("Root has no parent")]
    RootHasNoParent,

    #[error("Root has no siblings")]
    RootHasNoSiblings,

    #[error("Merkle tree nodes must be 32 bytes")]
    InvalidNodeLength,

    #[error("Expected non-zero number of leaves")]
    EmptyLeaves,

    #[error("Cannot prove duplicated index")]
    DuplicatedIndex,

    #[error("Invalid multiproof format")]
    InvalidMultiproofFormat,

    #[error("Provided leaves and multiproof are not compatible")]
    IncompatibleMultiproof,

    #[error("Leaf is not in tree")]
    LeafNotInTree,

    #[error("Index out of bounds")]
    IndexOutOfBounds,

    #[error("Unable to prove value")]
    UnableToProve,

    #[error("Merkle tree is invalid")]
    InvalidTree,

    #[error("Merkle tree does not contain the expected value")]
    ValueMismatch,

    #[error("Unknown format: {0}")]
    UnknownFormat(String),

    #[error("Expected leaf encoding")]
    MissingLeafEncoding,

    #[error("Hex decode error: {0}")]
    HexDecode(String),

    #[error("ABI encode error: {0}")]
    AbiEncode(String),
}

pub type Result<T> = std::result::Result<T, MerkleTreeError>;

#[inline]
pub fn validate_argument<T: AsRef<str>>(condition: bool, message: T) -> Result<()> {
    if !condition {
        Err(MerkleTreeError::InvalidArgument(
            message.as_ref().to_string(),
        ))
    } else {
        Ok(())
    }
}

#[inline]
pub fn invariant<T: AsRef<str>>(condition: bool, message: T) -> Result<()> {
    if !condition {
        Err(MerkleTreeError::Invariant(message.as_ref().to_string()))
    } else {
        Ok(())
    }
}
