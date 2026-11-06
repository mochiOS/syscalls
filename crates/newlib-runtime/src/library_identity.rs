//! Identity comes from fstat on the actual opened reference, never a pathname.
pub(super) const MAX_FILES: usize = 64;
#[derive(Clone, Copy)]
pub(super) struct Files {
    ids: [(u64, u64); MAX_FILES],
    count: usize,
}
impl Default for Files {
    fn default() -> Self {
        Self {
            ids: [(0, 0); MAX_FILES],
            count: 0,
        }
    }
}
impl Files {
    pub fn insert(&mut self, id: (u64, u64)) -> bool {
        if id == (0, 0) || self.count == MAX_FILES || self.ids[..self.count].contains(&id) {
            return false;
        }
        self.ids[self.count] = id;
        self.count += 1;
        true
    }
    pub fn intersects(&self, other: &Self) -> bool {
        self.ids[..self.count]
            .iter()
            .any(|id| other.ids[..other.count].contains(id))
    }
}
