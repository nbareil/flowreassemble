//! Byte ranges received out of order, with first-copy-wins overlap handling.
//!
//! Used by IP defragmentation and TCP reassembly. Stored segments never
//! overlap: when new data covers bytes already stored, the stored bytes win
//! and only the uncovered parts of the new data are kept.

use std::collections::BTreeMap;

#[derive(Default)]
pub struct Segments {
    map: BTreeMap<u64, Vec<u8>>,
    bytes: usize,
}

impl Segments {
    /// Stores `data` at `off`. Returns true if it overlaps stored bytes with
    /// different content.
    pub fn insert(&mut self, off: u64, data: &[u8]) -> bool {
        let end = off + data.len() as u64;
        let mut conflict = false;
        let mut cursor = off;
        let mut pieces = Vec::new();

        let before = self.map.range(..off).next_back().map(|(s, v)| (*s, v));
        let overlapping = before
            .into_iter()
            .chain(self.map.range(off..end).map(|(s, v)| (*s, v)));
        for (start, seg) in overlapping {
            let seg_end = start + seg.len() as u64;
            if seg_end <= cursor {
                continue;
            }
            if start > cursor {
                pieces.push((cursor, start));
            }
            let ov_start = start.max(cursor);
            let ov_end = seg_end.min(end);
            if ov_start < ov_end {
                let new = &data[(ov_start - off) as usize..(ov_end - off) as usize];
                let old = &seg[(ov_start - start) as usize..(ov_end - start) as usize];
                conflict |= new != old;
            }
            cursor = cursor.max(seg_end);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            pieces.push((cursor, end));
        }
        for (s, e) in pieces {
            let piece = data[(s - off) as usize..(e - off) as usize].to_vec();
            self.bytes += piece.len();
            self.map.insert(s, piece);
        }
        conflict
    }

    /// Removes and returns the segment starting exactly at `off`.
    pub fn pop_at(&mut self, off: u64) -> Option<Vec<u8>> {
        let seg = self.map.remove(&off)?;
        self.bytes -= seg.len();
        Some(seg)
    }

    /// Drops every stored byte at or after `from`.
    pub fn truncate(&mut self, from: u64) {
        let dropped = self.map.split_off(&from);
        self.bytes -= dropped.values().map(Vec::len).sum::<usize>();
        if let Some((start, seg)) = self.map.iter_mut().next_back() {
            let keep = from.saturating_sub(*start) as usize;
            if keep < seg.len() {
                self.bytes -= seg.len() - keep;
                seg.truncate(keep);
            }
        }
    }

    pub fn first_start(&self) -> Option<u64> {
        self.map.keys().next().copied()
    }

    pub fn end(&self) -> Option<u64> {
        self.map.iter().next_back().map(|(s, v)| s + v.len() as u64)
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// True if the stored segments cover `0..len` without holes.
    pub fn covers(&self, len: u64) -> bool {
        let mut cursor = 0;
        for (s, v) in &self.map {
            if *s != cursor {
                return false;
            }
            cursor += v.len() as u64;
        }
        cursor >= len
    }

    pub fn into_vec(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.bytes);
        for v in self.map.into_values() {
            out.extend_from_slice(&v);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_copy_wins_and_reports_conflicts() {
        let mut s = Segments::default();
        assert!(!s.insert(10, b"abcd"));
        assert!(s.insert(8, b"XXzzzzYY"));
        assert!(!s.insert(12, b"cd"));
        let mut out = Vec::new();
        let mut off = 8;
        while let Some(seg) = s.pop_at(off) {
            off += seg.len() as u64;
            out.extend(seg);
        }
        assert_eq!(out, b"XXabcdYY");
        assert!(s.is_empty());
        assert_eq!(s.bytes(), 0);
    }

    #[test]
    fn truncate_drops_bytes_from_an_offset() {
        let mut s = Segments::default();
        s.insert(0, b"abcd");
        s.insert(6, b"gh");
        s.truncate(2);
        assert_eq!(s.bytes(), 2);
        assert_eq!(s.end(), Some(2));
        assert_eq!(s.into_vec(), b"ab");
    }

    #[test]
    fn covers_detects_holes() {
        let mut s = Segments::default();
        s.insert(0, b"ab");
        s.insert(4, b"ef");
        assert!(!s.covers(6));
        s.insert(2, b"cd");
        assert!(s.covers(6));
        assert_eq!(s.into_vec(), b"abcdef");
    }
}
