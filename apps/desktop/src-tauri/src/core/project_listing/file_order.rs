use crate::core::project_listing::{native_path, PendingEntry, ProjectListing, RelPath, Walker};

impl ProjectListing {
    pub(in crate::core) fn file_order(&self) -> Vec<RelPath> {
        let mut paths = vec![None; self.files.len()];
        for (path, &index) in &self.listed_files {
            paths[index] = Some(path.clone());
        }
        paths.into_iter().flatten().collect()
    }
}

impl Walker<'_> {
    pub(super) fn sort_host_paths(&mut self) {
        let mut indexed: Vec<_> = std::mem::take(&mut self.files)
            .into_iter()
            .enumerate()
            .collect();
        indexed.sort_by_cached_key(|(_, file)| {
            let path = &file.relative;
            (
                path.components().count(),
                native_path(path),
                path.as_os_str().to_owned(),
            )
        });
        let mut positions = vec![0; indexed.len()];
        self.files.reserve(indexed.len());
        for (old, file) in indexed {
            positions[old] = self.files.len();
            self.files.push(file);
        }
        for (_, entry) in &mut self.entries {
            if let PendingEntry::File(index) = entry {
                *index = positions[*index];
            }
        }
    }
}
