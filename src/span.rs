//! Where positions found in parsed text land in the row it was cut from.

/// Moves a position in text a parser read to the row that text came from:
/// back through the bytes a scrub removed, then `base` bytes into the row.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Relocation<'a> {
    /// `(position in text, bytes removed before it)`, ascending.
    shifts: &'a [(usize, usize)],
    /// `None` when the text could not be placed in its row.
    base: Option<usize>,
    row: Option<usize>,
}

impl<'a> Relocation<'a> {
    /// Through the removals `shifts` records, staying in the same row.
    pub(crate) fn unshift(shifts: &'a [(usize, usize)]) -> Self {
        Relocation {
            shifts,
            base: Some(0),
            row: None,
        }
    }

    /// `base` bytes into row `row`.
    pub(crate) fn shift(base: Option<usize>, row: Option<usize>) -> Self {
        Relocation {
            shifts: &[],
            base,
            row,
        }
    }

    /// This relocation, then `base` bytes into row `row`.
    pub(crate) fn then_shift(self, base: Option<usize>, row: Option<usize>) -> Self {
        Relocation {
            base: self
                .base
                .zip(base)
                .map(|(a, b)| a + b),
            row,
            ..self
        }
    }

    /// Where the byte at `pos` came from.
    pub(crate) fn start(&self, pos: usize) -> Option<usize> {
        Some(self.base? + pos + self.removed(|at| at <= pos))
    }

    /// The row the text came from, when it names one.
    pub(crate) fn row(&self) -> Option<usize> {
        self.row
    }

    fn removed(&self, before: impl Fn(usize) -> bool) -> usize {
        self.shifts
            .iter()
            .take_while(|(at, _)| before(*at))
            .last()
            .map_or(0, |(_, removed)| *removed)
    }
}

/// Byte offset of `inner` within `outer`, when `inner` lies inside it.
pub(crate) fn row_offset(outer: &str, inner: &str) -> Option<usize> {
    let start = (inner.as_ptr() as usize).checked_sub(outer.as_ptr() as usize)?;
    (start + inner.len() <= outer.len()).then_some(start)
}
