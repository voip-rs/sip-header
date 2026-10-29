//! Walking a message's rows allocates only for a folded value.
//!
//! The counting allocator is process-wide, so this binary holds one test.
#![cfg(feature = "message")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use sip_header::{MessageLine, MessageLines};

struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Allocations made while walking `msg` and reading every row, once as text
/// and once as bytes; equal, or the test fails.
fn allocations(msg: &str) -> usize {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut seen = 0;
    for line in MessageLines::new(msg) {
        if let MessageLine::Row(row) = line {
            seen += row
                .name()
                .len()
                + row
                    .value()
                    .len()
                + row
                    .name_warnings()
                    .count();
        }
    }
    let text = ALLOCATIONS.load(Ordering::Relaxed) - before;
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for line in MessageLines::new(msg.as_bytes()) {
        if let MessageLine::Row(row) = line {
            seen += row
                .name()
                .len()
                + row
                    .value()
                    .len()
                + row
                    .text()
                    .map_or(0, |text| {
                        text.name_warnings()
                            .count()
                    });
        }
    }
    let bytes = ALLOCATIONS.load(Ordering::Relaxed) - before;
    std::hint::black_box(seen);
    assert_eq!(text, bytes, "{msg:?}");
    text
}

#[test]
fn only_a_folded_value_allocates() {
    let plain = concat!(
        "INVITE sip:bob@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1\r\n",
        "X Bad:\u{a0}a\u{b}\r\n",
        "no colon\r\n",
        "l: 0\r\n",
        "\r\n",
        "v=0\r\n",
    );
    assert_eq!(allocations(plain), 0);
    let folded = "Subject: a\r\n b\r\nTo: x\r\n \r\nVia: y\r\n\tz\r\n\r\n";
    assert_eq!(allocations(folded), 2);
}
