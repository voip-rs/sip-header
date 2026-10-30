# Performance

How the header reader spends its time, what was measured to get it there, and how to measure a change. The figures are workload- and build-specific; the cost model and the protocol in [Measuring a change](#measuring-a-change) are what carry over.

## Cost model of reading header rows

`MessageLines` is the one line rule; `SipMessageHeaders` collects what it yields. Per line it does:

- one LF search (the `memchr` crate), with one CR stripped;
- for a line not starting with SP or HTAB, one search for the first `:` and a trim back over SP and HTAB, which is all a row needs: a line with a colon after a non-empty name;
- a one-byte look at the next line to fold continuation lines into the row;
- nothing else. The blank line ends the walk where it is found, with no separate pass to find the end of the block.

Everything else is deferred to the caller:

- a name is classified (whitespace, non-ASCII, other non-token bytes, control characters) only when `name_warnings()` is called;
- a value is trimmed and unfolded only when `value()` is called, and allocates only to unfold a continuation;
- a byte row is validated as UTF-8 only when `text()` is called, on that row alone;
- whitespace beyond SP and HTAB at a value's edge stays in the row for the value parser that reads it.

The only check that reads a whole line as text is the start-line test, and it runs on the first line of a whole message only.

A caller after one header therefore pays, per row it does not want, a line search, a colon search and its own name comparison. `SipMessageHeaders` pays the same walk plus a name classification and a value per row.

## Measured path

A downstream trace parser frames SIP over TCP by Content-Length: about 10 header rows and 620 header bytes per message, one Content-Length row each. Its message splitting, before the reader was involved, was a vectorised line search and a 14-byte name compare per line. Level 2 splitting alone, over a 1 GB TCP capture, one pinned core:

| reader | instructions | elapsed |
|---|---|---|
| plain line scanner, no folding or name rules (floor) | 9.54G | 0.74-0.76 s |
| `SipMessageHeaders` built per message | 36.1G | 2.15 s |
| lazy walk, block pre-split, name classified per row | 28.6G | 1.7-1.8 s |
| one LF search per line, fused name loop, bytes in | 20.7G | 1.30 s |
| row needs only a colon; colon by `memchr`; inlined walk; Content-Length digit fast path | 13.8G | |
| caller gates on name length before matching | 12.2G | 0.90 s |
| caller frames with `blank_line_end()` instead of its own header-end search | 11.1G | 0.88 s |

The last row is 1.16x the floor in instructions and 1.17-1.19x in cycles. The same parser's full parse, which also builds `SipMessageHeaders` for every message, went from 47.4G to 44.8G instructions, so the cheaper reader paid for the diagnostics added beside it.

On a synthetic bench of 521-byte, 11-row blocks, stopping at the first Content-Length row, the walk costs about 218 instructions per row, about half of it the two `memchr` calls. Removing one would break the one-LF-search-per-line rule.

## Traps found on the way

- **A matcher rebuilt per row.** Before sip-header-catalog 1.0.0-rc.3, `SipHeader::matches` resolved the header on every call and a one-letter wire name went through a linear search of the compact forms; a caller building a `NameMatcher` per row spent about 10% of its run there. It is now cheap, and still the right shape for a loop is one `NameMatcher` built before it.
- **A non-generic helper does not inline across crates.** Without `#[inline]`, the line reader and the header-line scan showed up as their own symbols in a downstream profile. Generic code is monomorphized in the caller; a plain function is not.
- **A second pass that looks free.** Splitting the block off at the blank line before walking it, and rescanning the line read ahead after each row, made every byte go through the LF search three times. A caller searching for the header end before handing the block over adds another.
- **The walk over bytes did not beat the walk over text.** Validating UTF-8 per message first cost the same within 1%. Bytes are offered for callers that hold bytes, not as a speed lever.
- **The typed parse of a clean value.** `SipContentLength::parse_with_warnings` on plain digits went through the general scrub at about 630 instructions; the fast path takes about 135, and a property test holds it equal to the full path.

## Measuring a change

1. **Output identity first.** The change must produce the same rows, indexes, values, spans and warnings; a property test against a frozen copy of the previous reader is the cheapest proof while rewriting it, and it goes away once behaviour changes on purpose.
2. **Pin the core** (`taskset -c N`).
3. **Count instructions,** `perf stat -r 5 -e instructions:u,cycles:u`; the `:u` modifiers count user space only and need no privilege. Instruction counts reproduce to a few significant figures; wall clock does not.
4. **Subtract setup.** A bench that builds its corpus in-process measures that build too; run a mode that only builds it and subtract, per message.
5. **Interleave A/B/A/B,** and watch IPC: fewer instructions is not always faster.
6. **Profile before guessing** (`perf record -e instructions:u`, `perf report --no-children`). Every step in the table above was found this way.
