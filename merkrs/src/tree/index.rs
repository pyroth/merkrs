//! Flat-array index arithmetic for a complete binary Merkle tree.
//!
//! Index 0 is the root; children of `i` are at `2i + 1` and `2i + 2`.

use crate::error::{Error, Result};

#[inline]
pub(crate) const fn left_child(i: usize) -> usize {
    2 * i + 1
}

#[inline]
pub(crate) const fn right_child(i: usize) -> usize {
    2 * i + 2
}

#[inline]
pub(crate) const fn parent(i: usize) -> Result<usize> {
    if i == 0 {
        Err(Error::RootHasNoParent)
    } else {
        Ok((i - 1) / 2)
    }
}

#[inline]
pub(crate) const fn sibling(i: usize) -> Result<usize> {
    if i == 0 {
        Err(Error::RootHasNoSibling)
    } else if i % 2 == 1 {
        Ok(i + 1)
    } else {
        Ok(i - 1)
    }
}

#[inline]
pub(crate) const fn is_internal(tree_len: usize, i: usize) -> bool {
    left_child(i) < tree_len
}

#[inline]
pub(crate) const fn is_leaf(tree_len: usize, i: usize) -> bool {
    i < tree_len && !is_internal(tree_len, i)
}

pub(crate) const fn check_leaf(tree_len: usize, i: usize) -> Result<()> {
    if is_leaf(tree_len, i) {
        Ok(())
    } else {
        Err(Error::NotALeaf(i))
    }
}
