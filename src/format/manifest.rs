//! Binary manifest (`CManifestBin`): the directory tree of one depot version.
//!
//! ```text
//! header (0x38 bytes, 14 x u32):
//!   version(3|4), app_id, version_id, num_nodes, num_files, block_size,
//!   binary_size, string_table_size, hash_buckets, num_mfp_nodes,
//!   num_user_config_nodes, depot_info, fingerprint, checksum
//! nodes (0x1c bytes each, 7 x u32):
//!   name_offset, count_or_size, file_id, flags, parent, next_sibling, first_child
//! string table (NUL-terminated names)
//! ... hash buckets / mfp / user config nodes (ignored here)
//! ```
//!
//! The checksum is adler32 (seed 0) of the whole buffer with the fingerprint
//! and checksum fields zeroed.
//!
//! Only `parent` uses 0xffffffff as "none"; `first_child` and `next_sibling`
//! use 0 (the root can never be a child or sibling).

use super::{malformed, u32_at, Result};

pub const HEADER_SIZE: usize = 0x38;
pub const NODE_SIZE: usize = 0x1c;
pub const NO_NODE: u32 = u32::MAX;
pub const NO_FILE: u32 = u32::MAX;

/// Node flag bits (names follow HLLib's GCF manifest flags).
pub mod flags {
    /// Set on every file node.
    pub const FILE: u32 = 0x4000;
    /// The file's dat blocks are AES encrypted.
    pub const ENCRYPTED: u32 = 0x0100;
    /// Keep a local backup copy.
    pub const BACKUP_LOCAL: u32 = 0x0040;
    /// Copy out of the cache to disk at launch (executables, dlls).
    pub const COPY_LOCAL: u32 = 0x000a;
    /// Copy local, but never overwrite a user's copy.
    pub const COPY_LOCAL_NO_OVERWRITE: u32 = 0x0001;

    /// Comma-separated names for a flags word, unknown bits as hex.
    pub fn describe(mut v: u32) -> String {
        let mut out = Vec::new();
        for (bit, name) in [
            (FILE, "file"),
            (ENCRYPTED, "encrypted"),
            (BACKUP_LOCAL, "backup_local"),
            (COPY_LOCAL, "copy_local"),
            (COPY_LOCAL_NO_OVERWRITE, "copy_local_no_overwrite"),
        ] {
            if v & bit == bit {
                out.push(name.to_string());
                v &= !bit;
            }
        }
        if v != 0 {
            out.push(format!("{v:#x}"));
        }
        if out.is_empty() {
            "directory".to_string()
        } else {
            out.join(",")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    pub name_offset: u32,
    /// Child count for directories, byte size for files.
    pub count_or_size: u32,
    pub file_id: u32,
    pub flags: u32,
    pub parent: u32,
    pub next_sibling: u32,
    pub first_child: u32,
}

impl Node {
    pub fn is_dir(&self) -> bool {
        self.file_id == NO_FILE
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // header fields kept for inspection
pub struct Manifest {
    pub format_version: u32,
    pub app_id: u32,
    pub version_id: u32,
    pub depot_info: u32,
    pub fingerprint: u32,
    nodes: Vec<Node>,
    string_table: Vec<u8>,
    /// Every node that has a parent, sorted by (parent, name), so a child
    /// can be found by binary search against the string table - without a
    /// second copy of every name, or an allocation per lookup.
    by_name: Vec<u32>,
}

impl Manifest {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(malformed("manifest shorter than header"));
        }
        let hdr = |i: usize| u32_at(data, i * 4);
        let format_version = hdr(0)?;
        if format_version != 3 && format_version != 4 {
            return Err(malformed(format!(
                "manifest version {format_version} not 3 or 4"
            )));
        }
        let app_id = hdr(1)?;
        let version_id = hdr(2)?;
        let num_nodes = hdr(3)? as usize;
        let binary_size = hdr(6)? as usize;
        let string_table_size = hdr(7)? as usize;
        let block_size = hdr(5)?;
        let depot_info = hdr(11)?;
        let fingerprint = hdr(12)?;
        let expected_checksum = hdr(13)?;
        if u64::from(block_size) != super::BLOCK_SIZE {
            return Err(malformed(format!("manifest block size {block_size:#x}")));
        }
        if binary_size != data.len() {
            return Err(malformed(format!(
                "manifest binary_size {binary_size} != buffer {}",
                data.len()
            )));
        }
        let actual = checksum(data);
        if actual != expected_checksum {
            return Err(malformed(format!(
                "manifest checksum {actual:#010x} != header {expected_checksum:#010x}"
            )));
        }

        let nodes_end = HEADER_SIZE + num_nodes * NODE_SIZE;
        let strings_end = nodes_end + string_table_size;
        if strings_end > data.len() {
            return Err(malformed("manifest node/string tables exceed buffer"));
        }
        let mut nodes = Vec::with_capacity(num_nodes);
        for i in 0..num_nodes {
            let base = HEADER_SIZE + i * NODE_SIZE;
            let f = |j: usize| u32_at(data, base + j * 4);
            nodes.push(Node {
                name_offset: f(0)?,
                count_or_size: f(1)?,
                file_id: f(2)?,
                flags: f(3)?,
                parent: f(4)?,
                next_sibling: f(5)?,
                first_child: f(6)?,
            });
        }
        let string_table = data[nodes_end..strings_end].to_vec();

        let mut m = Self {
            format_version,
            app_id,
            version_id,
            depot_info,
            fingerprint,
            nodes,
            string_table,
            by_name: Vec::new(),
        };
        for (i, n) in m.nodes.iter().enumerate() {
            if n.name_offset as usize >= m.string_table.len() {
                return Err(malformed(format!("node {i}: name offset out of range")));
            }
            if n.parent != NO_NODE && n.parent as usize >= m.nodes.len() {
                return Err(malformed(format!("node {i}: parent out of range")));
            }
            // `first_child`/`next_sibling` terminate at 0 (and, defensively,
            // at NO_NODE); anything else must be a real node, or walking the
            // tree would index out of bounds.
            for (link, what) in [
                (n.first_child, "first child"),
                (n.next_sibling, "next sibling"),
            ] {
                if link != 0 && link != NO_NODE && link as usize >= m.nodes.len() {
                    return Err(malformed(format!("node {i}: {what} {link} out of range")));
                }
            }
        }
        let mut by_name: Vec<u32> = (0..m.nodes.len() as u32)
            .filter(|i| m.nodes[*i as usize].parent != NO_NODE)
            .collect();
        by_name.sort_by(|a, b| m.sort_key(*a).cmp(&m.sort_key(*b)));
        m.by_name = by_name;
        Ok(m)
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    pub fn node(&self, idx: u32) -> Option<&Node> {
        self.nodes.get(idx as usize)
    }

    /// Raw name bytes of a node (names are not guaranteed to be UTF-8).
    /// Empty for an unknown node; `parse` has already range-checked every
    /// name offset, so a real node always has a name.
    pub fn name(&self, idx: u32) -> &[u8] {
        let Some(start) = self.nodes.get(idx as usize).map(|n| n.name_offset as usize) else {
            return &[];
        };
        let rest = &self.string_table[start..];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        &rest[..end]
    }

    /// The root node index (parent == NO_NODE), normally 0.
    pub fn root(&self) -> u32 {
        self.nodes
            .iter()
            .position(|n| n.parent == NO_NODE)
            .map_or(0, |i| i as u32)
    }

    /// Iterate a directory's children in sibling order.
    pub fn children(&self, dir: u32) -> Children<'_> {
        let n = self.nodes.get(dir as usize);
        Children {
            manifest: self,
            next: n.map_or(0, |n| n.first_child),
            remaining: n.map_or(0, |n| if n.is_dir() { n.count_or_size } else { 0 }),
        }
    }

    fn sort_key(&self, idx: u32) -> (u32, &[u8]) {
        (
            self.nodes.get(idx as usize).map_or(NO_NODE, |n| n.parent),
            self.name(idx),
        )
    }

    pub fn child_by_name(&self, dir: u32, name: &[u8]) -> Option<u32> {
        let i = self
            .by_name
            .binary_search_by(|idx| self.sort_key(*idx).cmp(&(dir, name)))
            .ok()?;
        self.by_name.get(i).copied()
    }

    /// Full path of a node, `/`-joined, without a leading slash.
    pub fn path(&self, idx: u32) -> Vec<u8> {
        let mut parts = Vec::new();
        let mut cur = idx;
        while let Some(n) = self.node(cur) {
            if n.parent == NO_NODE {
                break;
            }
            parts.push(self.name(cur));
            cur = n.parent;
        }
        parts.reverse();
        parts.join(&b'/')
    }
}

pub struct Children<'a> {
    manifest: &'a Manifest,
    next: u32,
    /// Bounded by the directory's child count so a corrupt chain cannot loop.
    remaining: u32,
}

impl Iterator for Children<'_> {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.next == 0 || self.next == NO_NODE || self.remaining == 0 {
            return None;
        }
        let cur = self.next;
        self.remaining -= 1;
        let Some(node) = self.manifest.node(cur) else {
            self.next = 0;
            return None;
        };
        self.next = node.next_sibling;
        Some(cur)
    }
}

/// adler32 with seed 0 over the buffer with the fingerprint (0x30) and
/// checksum (0x34) fields treated as zero.
fn checksum(data: &[u8]) -> u32 {
    let mut a = adler2::Adler32::from_checksum(0);
    a.write_slice(&data[..0x30]);
    a.write_slice(&[0u8; 8]);
    a.write_slice(&data[0x38..]);
    a.checksum()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Build a manifest buffer: root -> [dir "a" -> [file "x"], file "y"].
    fn sample() -> Vec<u8> {
        let names = b"\0a\0x\0y\0";
        let nodes: [[u32; 7]; 4] = [
            // name, count/size, file_id, flags, parent, next_sibling, first_child
            [0, 2, NO_FILE, 0, NO_NODE, 0, 1],
            [1, 1, NO_FILE, 0, 0, 3, 2],
            [3, 10, 7, flags::FILE, 1, 0, 0],
            [5, 20, 8, flags::FILE, 0, 0, 0],
        ];
        let mut buf = vec![0u8; HEADER_SIZE];
        for n in &nodes {
            for v in n {
                buf.extend_from_slice(&v.to_le_bytes());
            }
        }
        buf.extend_from_slice(names);
        let mut hdr = [0u32; 14];
        hdr[0] = 4;
        hdr[1] = 99;
        hdr[3] = nodes.len() as u32;
        hdr[4] = 2;
        hdr[5] = 0x8000;
        hdr[6] = buf.len() as u32;
        hdr[7] = names.len() as u32;
        hdr[12] = 0xabcd;
        for (i, v) in hdr.iter().enumerate() {
            buf[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        let ck = checksum(&buf);
        buf[0x34..0x38].copy_from_slice(&ck.to_le_bytes());
        buf
    }

    #[test]
    fn walks_tree() {
        let m = Manifest::parse(&sample()).unwrap();
        assert_eq!(m.app_id, 99);
        assert_eq!(m.children(0).collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(m.children(1).collect::<Vec<_>>(), vec![2]);
        assert_eq!(m.children(2).count(), 0);
        assert_eq!(m.child_by_name(0, b"a"), Some(1));
        assert_eq!(m.child_by_name(1, b"x"), Some(2));
        assert_eq!(m.path(2), b"a/x");
        assert!(m.node(2).unwrap().flags & flags::FILE != 0);
        assert_eq!(m.fingerprint, 0xabcd);
        assert_eq!(flags::describe(0x400a), "file,copy_local");
        assert_eq!(flags::describe(0x4100), "file,encrypted");
        assert_eq!(flags::describe(0), "directory");
    }

    /// Rebuild a manifest buffer after mutating one node field.
    fn with_node_field(node: usize, field: usize, value: u32) -> Vec<u8> {
        let mut buf = sample();
        let off = HEADER_SIZE + node * NODE_SIZE + field * 4;
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
        let zeroed = {
            let mut b = buf.clone();
            b[0x30..0x38].fill(0);
            b
        };
        let ck = checksum(&zeroed);
        buf[0x34..0x38].copy_from_slice(&ck.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_out_of_range_links() {
        // field 6 is first_child, field 5 is next_sibling.
        assert!(Manifest::parse(&with_node_field(0, 6, 99)).is_err());
        assert!(Manifest::parse(&with_node_field(1, 5, 99)).is_err());
        // 0 and NO_NODE are terminators, not indices.
        assert!(Manifest::parse(&with_node_field(2, 5, 0)).is_ok());
        assert!(Manifest::parse(&with_node_field(2, 5, NO_NODE)).is_ok());
    }

    #[test]
    fn finds_every_child_by_name() {
        let m = Manifest::parse(&sample()).unwrap();
        for (i, n) in m.nodes().iter().enumerate() {
            if n.parent == NO_NODE {
                continue;
            }
            assert_eq!(
                m.child_by_name(n.parent, m.name(i as u32)),
                Some(i as u32),
                "node {i}"
            );
        }
        assert_eq!(m.child_by_name(0, b"nope"), None);
        assert_eq!(m.child_by_name(99, b"a"), None);
        // A name that exists, but under a different parent.
        assert_eq!(m.child_by_name(0, b"x"), None);
    }

    #[test]
    fn unknown_node_has_no_name() {
        let m = Manifest::parse(&sample()).unwrap();
        assert_eq!(m.name(999), b"");
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut buf = sample();
        buf[0x34] ^= 1;
        assert!(Manifest::parse(&buf).is_err());
    }
}
