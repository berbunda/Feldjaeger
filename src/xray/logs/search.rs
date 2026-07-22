//! Local text search over already-loaded Xray log lines.
//!
//! Search never issues remote commands.

use super::model::XrayLogEntry;

/// Case-insensitive search state over the currently loaded entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XrayLogSearch {
    /// Active query (empty = no search).
    pub query: String,
    /// Match indexes into the entry list (stable order).
    pub match_indexes: Vec<usize>,
    /// Currently highlighted match within [`match_indexes`](Self::match_indexes).
    pub current: Option<usize>,
}

impl XrayLogSearch {
    /// Rebuilds matches for `query` against `entries`.
    pub fn recompute(&mut self, entries: &[XrayLogEntry], query: &str) {
        self.query = query.to_owned();
        self.match_indexes.clear();
        self.current = None;

        let needle = query.trim();
        if needle.is_empty() {
            return;
        }

        let needle_lower = needle.to_ascii_lowercase();
        for (index, entry) in entries.iter().enumerate() {
            if entry
                .display_text()
                .to_ascii_lowercase()
                .contains(&needle_lower)
            {
                self.match_indexes.push(index);
            }
        }

        if !self.match_indexes.is_empty() {
            self.current = Some(0);
        }
    }

    /// Number of matches.
    pub fn match_count(&self) -> usize {
        self.match_indexes.len()
    }

    /// Absolute entry index of the current match, if any.
    pub fn current_entry_index(&self) -> Option<usize> {
        self.current
            .and_then(|i| self.match_indexes.get(i).copied())
    }

    /// Advance to the next match (wraps).
    pub fn next(&mut self) -> Option<usize> {
        if self.match_indexes.is_empty() {
            self.current = None;
            return None;
        }
        let next = match self.current {
            Some(i) => (i + 1) % self.match_indexes.len(),
            None => 0,
        };
        self.current = Some(next);
        self.current_entry_index()
    }

    /// Move to the previous match (wraps).
    pub fn previous(&mut self) -> Option<usize> {
        if self.match_indexes.is_empty() {
            self.current = None;
            return None;
        }
        let prev = match self.current {
            Some(0) | None => self.match_indexes.len() - 1,
            Some(i) => i - 1,
        };
        self.current = Some(prev);
        self.current_entry_index()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(lines: &[&str]) -> Vec<XrayLogEntry> {
        lines.iter().map(|line| XrayLogEntry::plain(*line)).collect()
    }

    #[test]
    fn case_insensitive_local_search() {
        let list = entries(&["Hello World", "goodbye", "HELLO again"]);
        let mut search = XrayLogSearch::default();
        search.recompute(&list, "hello");
        assert_eq!(search.match_count(), 2);
        assert_eq!(search.current_entry_index(), Some(0));
        assert_eq!(search.next(), Some(2));
        assert_eq!(search.previous(), Some(0));
    }

    #[test]
    fn empty_query_clears_matches() {
        let list = entries(&["a", "b"]);
        let mut search = XrayLogSearch::default();
        search.recompute(&list, "a");
        assert_eq!(search.match_count(), 1);
        search.recompute(&list, "  ");
        assert_eq!(search.match_count(), 0);
        assert!(search.current.is_none());
    }
}
