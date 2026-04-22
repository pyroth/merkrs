//! ASCII rendering of the flat tree array for debugging.

use std::fmt::Write as _;

use super::index::{left_child, right_child};
use crate::bytes::{Bytes32, encode_hex};
use crate::error::{Error, Result};

/// Render a tree as an indented ASCII string.
pub(crate) fn render(tree: &[Bytes32]) -> Result<String> {
    if tree.is_empty() {
        return Err(Error::EmptyLeaves);
    }

    let mut output = String::new();
    let mut stack: Vec<(usize, Vec<bool>)> = vec![(0, vec![])];

    while let Some((i, path)) = stack.pop() {
        for &is_continuation in path.iter().take(path.len().saturating_sub(1)) {
            output.push_str(if is_continuation { "│  " } else { "   " });
        }
        if let Some(&is_left) = path.last() {
            output.push_str(if is_left { "├─ " } else { "└─ " });
        }

        let node = tree.get(i).ok_or(Error::IndexOutOfBounds {
            index: i,
            len: tree.len(),
        })?;
        _ = writeln!(output, "{i}) {}", encode_hex(node));

        let r = right_child(i);
        if r < tree.len() {
            let mut right_path = path.clone();
            right_path.push(false);
            stack.push((r, right_path));

            let mut left_path = path;
            left_path.push(true);
            stack.push((left_child(i), left_path));
        }
    }

    if output.ends_with('\n') {
        output.pop();
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::super::builder::build;
    use super::*;
    use crate::hashes::{keccak256, standard_node_hash};

    fn test_leaves(count: usize) -> Vec<Bytes32> {
        (0..count)
            .map(|i| {
                #[expect(clippy::cast_possible_truncation, reason = "test helper, i < 256")]
                let b = i as u8;
                keccak256(&[b])
            })
            .collect()
    }

    #[test]
    fn render_tree() {
        let leaves = test_leaves(2);
        let tree = build(&leaves, standard_node_hash).unwrap();
        let text = render(&tree).unwrap();
        assert!(text.contains("0)"), "should contain root index");
        assert!(text.contains("0x"), "should contain hex hashes");
    }
}
