#[derive(Debug, Clone, Copy)]
pub struct MerkleTreeOptions {
    pub sort_leaves: bool,
}

impl Default for MerkleTreeOptions {
    fn default() -> Self {
        Self { sort_leaves: true }
    }
}

impl MerkleTreeOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sort_leaves(mut self, sort: bool) -> Self {
        self.sort_leaves = sort;
        self
    }
}
