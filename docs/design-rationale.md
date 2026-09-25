# Design Rationale

## Comma lists split through one quote- and bracket-aware splitter

Every list header splits through `split_comma_entries`, which skips commas inside `<...>` and inside quoted strings (honouring `quoted-pair`). No header gets a private splitter, because a list entry's quoted string (Warning's warn-text, an auth param, a display name) is as likely to hold a comma as its URI is.

Quote state is tracked only at bracket depth zero. A conformant header never carries a quote inside `<...>`, so the guard costs nothing there; on malformed input it keeps a stray quote from holding the bracket open and swallowing every entry after it.

## Header parameters parse through one quote-aware reader

Every `*(SEMI generic-param)` tail is read by the shared parameter reader in `lib.rs`, so a fix to parameter grammar (SWS around `;` and `=`, a `;` inside a quoted `gen-value`) reaches every header at once. The reader hands back the value as it appeared on the wire, quotes included; each type decides whether its accessors unescape, so a type's public values stay what its callers already compare against.

A quote that never closes is not a quoted-string, and the reader falls back to splitting at the next `;`. Treating it as open would let one stray quote erase the mandatory parameters after it.

## Parameter quotedness survives a round trip

Types that store unescaped values keep, per parameter, whether it arrived quoted, and Display re-quotes exactly those, plus any value that could not be emitted bare. Whether a parameter must be quoted depends on the role the header plays: a Digest challenge quotes `qop`, a credential does not, and one `SipAuthValue` serves both. The wire form is therefore the only reliable source.

## header_addr keeps its own quoted-string reader

`quoted-pair` escaping and unescaping for Warning, auth params and display-name output share the `lib.rs` helpers. The name-addr parser's quoted-string reader is the exception: it tracks the position where the quoted string ends so parsing can continue after it, and bolting that onto the shared unescaper would give every other caller a return value it has no use for.

## Body extraction shares the header boundary

Callers re-deriving the header/body boundary as `split_once("\r\n\r\n")` silently lose the body on bare-`\n` messages this crate accepts, so `extract_body` and the header extractors share one boundary helper. The splitter stays private: a public one would freeze header-block slice semantics we haven't needed to define, and exposing it later is non-breaking.

## Replaces framing is an explicit constructor

`SipReplaces` (and `SipTargetDialog`) parse both the wire header value and the hnv-encoded (hnv = RFC 3261 section 25 `hname`/`hvalue` charset) URI-header form found inside a Refer-To, where `@`, `;` and `=` remain percent-encoded after sip-uri's canonicalisation. `%` is a legal call-id `word` character, so a value cannot reveal which framing it is in: `parse` and `parse_uri_header` are separate constructors, and Display re-emits the framing the instance was parsed from. The encoded framing re-encodes to canonical hnv form (uppercase hex), matching sip-uri's canonicalised output, so round-trip is against that form rather than the producer's original hex casing.

## Reason text decodes as hvalue with `+` literal

A Reason embedded in a URI header is percent-decoded and nothing else. sip-uri returns the same literal `+` whether the producer sent `+` or `%2B`, so a `+`-as-space convention cannot be applied after parsing without corrupting real plus signs. A caller that knows its producer form-encodes converts them itself.

## Conference-info normalization drops foreign-namespace subtrees

Namespace prefixes are stripped before deserialization, so an element is matched by local name alone. Below the root, an element bound to a declared namespace that is neither conference-info nor the root's own is dropped with its subtree; otherwise an extension element named like a base element would deserialize as one. Unbound and undeclared prefixes are still stripped, and the root is never dropped, so documents with a nonstandard namespace declaration keep parsing.

## Mutators validate against the grammar their parser does not enforce

A parser's leniency is what makes real traffic survivable; a value handed to a mutator never crossed the wire, so it earns none of that. An unchecked Call-ID set on a dialog identifier re-serializes into a header naming a different dialog, and an unchecked display name can carry a line break into the next header. Public mutators and builders therefore return `Result` and check the RFC production for the field they set, and the resulting asymmetry stands: a value `parse` accepted can be rejected when set back through a mutator.

## Parsers are lenient; warnings report what strict parsing would refuse

Every header-value type parses the way sip-uri does, so the two crates read one way: `FromStr` keeps whatever value the input yields, `parse_with_warnings` returns it with the grammar breaches found on the way, and `parse_strict` refuses the first one. A warning names the field, a code, a byte position in the string handed to the parser, and for list types the entry index; it never carries the text, which may be a caller's number. Whether the value still holds what was sent is fixed by the code, not chosen per call site, so one code means the same thing everywhere it is raised. A URI's own warnings pass through with their sip-uri component and code, shifted to the header's positions.

## FromStr fails only where no value exists

`FromStr` returns `Err` for input that yields no usable value: empty where the grammar requires content, or a structure the RFC makes the receiver reject outright, such as a second Replaces. Every other breach becomes a warning, so tightening a parser means adding a warning code, never a new rejection.

## One error type for every header value

Every header-value parser returns the crate's `ParseError`, so nested parsers compose with `?` and a consumer matches one type. A failed URI keeps sip-uri's error as its source rather than a string, and the strict path has one shape: a URI breach under `parse_strict` surfaces as the same non-conformance a header breach does. The conference-info body is XML, not a header value, and keeps its own error, whose source is the XML reader's; header-name catalogs keep theirs, because an unknown name is not a malformed value.

## Multi-occurrence headers stay one entry per occurrence

`extract_header` returns one value per occurrence, never a comma-joined string, because RFC 3261 section 7.3.1 forbids joining the authentication headers. `SipHeaderLookup` exposes every occurrence through `sip_header_all_str` / `sip_header_all`, and every list accessor reads through them, splitting each row untrimmed. A present row that is only whitespace therefore reaches the entry parser as an empty entry instead of vanishing. The exception is a header whose grammar admits an empty value, where a blank row is the empty list.

## Error Display never carries the rejected bytes

An error renders a label, the field or position at fault, and the length of the rejected input, never the input itself. A type that keeps the bytes keeps them on a public field, for a caller that decides to print them. Display reaches every consumer's `{e}` log line outside whatever redaction the consumer applies, and header values carry credentials, retrieval tokens and caller numbers.

## List-valued types take pre-split entries

Every comma-list type has a `from_entries` constructor beside `parse`, and a problem in one entry surfaces as a warning carrying that entry's index. A caller holding entries a transport already delimited never re-joins them for `parse`: the second split is a guess over boundaries already drawn, and it hides which layer produced a bad entry.
