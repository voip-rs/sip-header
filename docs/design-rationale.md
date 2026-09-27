# Design Rationale

## Comma lists split through one quote- and bracket-aware splitter

Every list header splits through `split_comma_entries`, which skips commas inside `<...>` and inside quoted strings (honouring `quoted-pair`). No header gets a private splitter, because a list entry's quoted string (Warning's warn-text, an auth param, a display name) is as likely to hold a comma as its URI is.

Quote state is tracked only at bracket depth zero. A conformant header never carries a quote inside `<...>`, so the guard costs nothing there; on malformed input it keeps a stray quote from holding the bracket open and swallowing every entry after it.

## Header parameters parse through one quote-aware reader

Every `*(SEMI generic-param)` tail is read by the shared parameter reader in `lib.rs`, so a fix to parameter grammar (SWS around `;` and `=`, a `;` inside a quoted `gen-value`) reaches every header at once.

A quote that never closes is not a quoted-string, and the reader falls back to splitting at the next `;`. Treating it as open would let one stray quote erase the mandatory parameters after it.

## Header parameters are one type

Every value type holds its parameters in `HeaderParams`, so key case, quoting, duplicates and serde behave one way across headers. Values are stored unescaped with, per parameter, whether it arrived quoted; Display re-quotes exactly those, plus any value that is neither a token nor a host, and the parser warns about a bare value it will have to re-quote. Whether a parameter must be quoted depends on the role the header plays: a Digest challenge quotes `qop`, a credential does not, and one `SipAuthValue` serves both, so the wire form is the only reliable source and quotedness is part of equality.

Setting a key that exists replaces its value in place and drops its later repeats. A key its owner sets through a typed setter (a tag, `rport`, `index`) is refused by the generic setter, since a second copy would print a header naming something else. Duplicates arriving from the wire are kept and warned about, and lookup returns the first. Equality ignores order across keys but not among one key's values, because lookup would otherwise tell two equal values apart. Parameters are never percent-decoded: `%` is a token character in header parameters. Serde carries a reserved key as a field of its own, holding its first occurrence when that is in the form the typed setter writes; repeats and other forms stay among the parameters. Deserialize must read back every value the parser can produce, repeats included, and accepts a value only when parsing its own wire form yields it again.

## header_addr keeps its own quoted-string reader

`quoted-pair` escaping and unescaping for Warning, auth params and display-name output share the `lib.rs` helpers. The name-addr parser's quoted-string reader is the exception: it tracks the position where the quoted string ends so parsing can continue after it, and bolting that onto the shared unescaper would give every other caller a return value it has no use for.

## Body extraction shares the header boundary

Callers re-deriving the header/body boundary as `split_once("\r\n\r\n")` silently lose the body on bare-`\n` messages this crate accepts, so `extract_body` and the header extractors share one boundary helper. The splitter stays private: a public one would freeze header-block slice semantics we haven't needed to define, and exposing it later is non-breaking.

## Replaces framing is an explicit constructor

`SipReplaces` (and `SipTargetDialog`) parse both the wire header value and the hnv-encoded (hnv = RFC 3261 section 25 `hname`/`hvalue` charset) URI-header form found inside a Refer-To, where `@`, `;` and `=` remain percent-encoded after sip-uri's canonicalisation. `%` is a legal call-id `word` character, so a value cannot reveal which framing it is in: `parse` and `parse_uri_header` are separate constructors, and Display re-emits the framing the instance was parsed from. The encoded framing re-encodes to canonical hnv form (uppercase hex), matching sip-uri's canonicalised output, so round-trip is against that form rather than the producer's original hex casing.

## Reason text decodes as hvalue with `+` literal

A Reason embedded in a URI header is percent-decoded and nothing else. `hvalue` gives `+` no meaning, and reading it as a space would corrupt the real plus signs a producer left unescaped. A caller that knows its producer form-encodes converts them itself, from the raw value.

## Conference-info normalization drops foreign-namespace subtrees

Namespace prefixes are stripped before deserialization, so an element is matched by local name alone. Below the root, an element bound to a declared namespace that is neither conference-info nor the root's own is dropped with its subtree; otherwise an extension element named like a base element would deserialize as one. Unbound and undeclared prefixes are still stripped, and the root is never dropped, so documents with a nonstandard namespace declaration keep parsing.

## Constructors refuse what would print as a different value

A parser's leniency is what makes real traffic survivable; a value handed to a constructor or builder never crossed the wire, so it earns none of that. An unchecked Call-ID set on a dialog identifier re-serializes into a header naming a different dialog, and an unchecked display name can carry a line break into the next header. Every constructor, builder and deserializer therefore returns `Result`, and a value built through them prints something `parse_strict` reads back as the same value: control characters, a field's own delimiter, empty mandatory parts and out-of-range numbers are refused. NUL is refused even as a `quoted-pair` the grammar allows, and `<` inside a URI, because either would re-frame the value for a downstream reader. The resulting asymmetry stands: a value `parse` accepted can be rejected when set back through a builder.

A leniently parsed value is not held to strict round-trip, only to safety: it never prints a CR, LF or NUL, and parsing its output yields it again. A folded line is whitespace and becomes one space; any other control character is dropped with a warning.

## Parsers are lenient; warnings report what strict parsing would refuse

Every header-value type parses the way sip-uri does, so the two crates read one way: `HeaderParse::parse` keeps whatever value the input yields, `parse_with_warnings` returns it with the grammar breaches found on the way, and `parse_strict` refuses the first one. A warning names the field, a code, a byte position in the string handed to the parser, and for list types the entry index; it never carries the text, which may be a caller's number. Whether the value still holds what was sent is fixed by the code, not chosen per call site, so one code means the same thing everywhere it is raised. A URI's own warnings pass through with their sip-uri component and code, shifted to the header's positions, and their code's name is prefixed so one name identifies one code across both crates.

## Lenient parsing fails only where no value exists

`HeaderParse::parse` returns `Err` for input that yields no usable value: empty where the grammar requires content, or a structure the RFC makes the receiver reject outright, such as a second Replaces. Every other breach becomes a warning, so tightening a parser means adding a warning code, never a new rejection. Where a type cannot hold what the input carries, such as a wildcard beside addresses or a Via entry without a host, the parser drops that part under a warning whose kind says data was lost.

## One error type for every header value

Every header-value parser returns the crate's `ParseError`, so nested parsers compose with `?` and a consumer matches one type. A failed URI keeps sip-uri's error as its source rather than a string, and the strict path has one shape: a URI breach under `parse_strict` surfaces as the same non-conformance a header breach does. A framing fault a lookup store reports arrives as the catalog's row error and is carried whole as the source, never mapped onto our fault codes, because the catalog's kinds are open-ended and a mapping would lose the ones added later. Display names the failing layer and leaves the cause to `source()`, so a chain printer shows each cause once. `ParseError` stays `Clone` and `Eq` so callers can compare and keep it; no source it carries may therefore be a boxed foreign error. The conference-info body is XML, not a header value, and keeps its own error, whose source is the XML reader's; header-name catalogs keep theirs, because an unknown name is not a malformed value.

## Stores return one row per occurrence, borrowed and fallible

`extract_header` and every lookup store return one row per header occurrence, never a comma-joined string, because RFC 3261 section 7.3.1 forbids joining the authentication headers; splitting a row into list entries is the accessor's job, and each row is split untrimmed. A store has one required method, the fallible rows lookup, and everything else, the single-value lookup included, derives from it, so two views of one store cannot disagree and a store's decoding failure reaches every caller instead of a value parsed from undecoded text. Rows are borrowed from the store: a store that must unfold or unescape does it once when it is built, never per lookup. A present row that is only whitespace reaches the entry parser as an empty entry instead of vanishing, except where the header's grammar admits an empty value.

Callers pass the canonical name. A store keyed by wire name matches it case-insensitively and through the compact alias, using the catalog's predicate, and returns both spellings in wire order; a store keyed another way translates the name and looks it up directly.

## Only the header catalog is a stable crate

The header-name catalog and the raw row trait are a crate of their own that aims for 1.0, because a consumer that puts a header store or header names in its public API would otherwise take a major version with every parser minor. Value types stay in sip-header with their parsers: their shapes are still being settled against real traffic, and a frozen value crate would freeze each open question with it.

## Parsing is spelled through extension traits

Parsing and redaction are extension traits a caller imports (`HeaderParse`, `ListParse` and their siblings, gathered in the prelude), matching sip-uri's `UriParse`, so the two crates read one way. Should value types later move to a crate of their own, the orphan rule would force traits anyway; spelling them as traits now keeps that move from breaking callers.

## Lookup stores implement the raw row trait

A store implements `SipHeaderRows` from the catalog and receives every typed accessor from sip-header by blanket impl. A consumer's public API then names only the stable crate, while callers choose their own sip-header version for the accessors.

## Comma-list and repeatable are separate predicates

The catalog says of each header whether its grammar is a comma list, safe to split and join, and separately whether it may occur more than once. The authentication headers may repeat but are not lists, and a store that splits every repeatable header at commas cuts a credential apart. Each classification cites the header's ABNF.

## Non-IANA headers are always present

Headers from expired drafts that remain deployed are ordinary catalog entries, with an accessor reporting which registry they come from. A cargo feature would change what parses for every crate in a build as soon as one crate enabled it, and a header later registered by IANA changes only that accessor's answer.

## Catalog serde uses the wire name

A header name serializes as its canonical wire spelling and deserializes from any spelling the parser accepts, so stored data survives a variant rename and matches what a human writes in a config file. Enums built with the catalog's macro get the same serde only when their invocation asks for it, since a feature enabled elsewhere in a build must not add impls to a caller's type.

## Error Display never carries the rejected bytes

An error renders a label, the field or position at fault, and the length of the rejected input, never the input itself. A type that keeps the bytes keeps them on a public field, for a caller that decides to print them. Display reaches every consumer's `{e}` log line outside whatever redaction the consumer applies, and header values carry credentials, retrieval tokens and caller numbers.

## List-valued types take pre-split entries

Every comma-list type has a `from_entries` constructor beside `parse`, and a problem in one entry surfaces as a warning carrying that entry's index. A caller holding entries a transport already delimited never re-joins them for `parse`: the second split is a guess over boundaries already drawn, and it hides which layer produced a bad entry.
