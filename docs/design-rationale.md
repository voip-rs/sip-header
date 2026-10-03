# Design Rationale

## Comma lists split through one quote- and bracket-aware splitter

Every list header splits through `split_comma_entries`, which skips commas inside `<...>` and inside quoted strings (honouring `quoted-pair`). No header gets a private splitter, because a list entry's quoted string (Warning's warn-text, an auth param, a display name) is as likely to hold a comma as its URI is. The splitter frames the row with its control characters dropped, as the entry parsers read it, while each entry stays a slice of the row as handed in, so a dropped character never moves a boundary.

A `"` opens a quoted string only at bracket depth zero, only where the list's grammar lets one start (a display name, a parameter value, warn-text), and only when it closes; any other quote is ordinary text. The public splitter, which does not know the grammar, accepts the union of those positions. A stray quote therefore never holds commas, and printing a leniently parsed list cannot pair it with a later quote and reframe the entries. Text after a final comma is not an entry, but the comma is reported; the public splitter has a reporting sibling so a caller that splits and then builds from entries does not lose that breach.

## Token fields drop stray framing

A `"`, `<`, `>` or `,` inside a token field is dropped by the lenient parser under a warning whose kind says data was lost, so no printed token carries list framing into the next reader. A token has no escape form, so where a URI component keeps such text escaped, a token can only lose it; the span still reaches it. A tag the parameter reader framed as a closed quoted value is kept verbatim, because it prints with the same framing it arrived with.

## Header parameters parse through one quote-aware reader

Every `*(SEMI generic-param)` tail is read by the shared parameter reader in `lib.rs`, so a fix to parameter grammar (SWS around `;` and `=`, a `;` inside a quoted `gen-value`) reaches every header at once. The reader starts at the opening `;`, so a `;` with no parameter after it is reported wherever it appears.

A quote that never closes is not a quoted-string, and the reader falls back to splitting at the next `;`. Treating it as open would let one stray quote erase the mandatory parameters after it.

## Header parameters are one type

Every value type holds its parameters in `HeaderParams`, so key case, quoting, duplicates and serde behave one way across headers. Values are stored unescaped with, per parameter, whether it arrived quoted; Display re-quotes exactly those, plus any value that is neither a token nor a host, and the parser warns about a bare value it will have to re-quote. Whether a parameter must be quoted depends on the role the header plays: a Digest challenge quotes `qop`, a credential does not, and one `SipAuthValue` serves both, so the wire form is the only reliable source and quotedness is part of equality.

Setting a key that exists replaces its value in place and drops its later repeats. A value's parameters change only through its owner's guard, which runs the builders' check and clears the value's spans. A key its owner sets through a typed setter (a tag, `rport`, `index`) is refused by every generic operation, removal included, since a second copy or a missing one prints a header naming something else. Duplicates arriving from the wire are kept and warned about, and lookup returns the first; adding a name a built value already holds is refused, since strict parsing refuses the repeat. Parameters are never percent-decoded: `%` is a token character in header parameters. Serde writes the parameters as held, in order, reserved keys among them, since equality counts their position. Deserialize must read back every value the parser can produce, repeats included, and accepts a value only when parsing its own wire form yields it again.

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

A parser's leniency is what makes real traffic survivable; a value handed to a constructor or builder never crossed the wire, so it earns none of that. An unchecked Call-ID set on a dialog identifier re-serializes into a header naming a different dialog, and an unchecked display name can carry a line break into the next header. Every constructor, builder and deserializer therefore returns `Result`, and a value built through them prints something `parse_strict` reads back as the same value: control characters, a field's own delimiter, empty mandatory parts and out-of-range numbers are refused. NUL is refused even as a `quoted-pair` the grammar allows, and `<` inside a URI, because either would re-frame the value for a downstream reader. A URI or host handed to a constructor must itself read back strictly. A list whose grammar needs an entry cannot be built or mutated empty. The resulting asymmetry stands: a value `parse` accepted can be rejected when set back through a builder.

A leniently parsed value is not held to strict round-trip, only to safety: it never prints a CR, LF or NUL, and parsing its output yields it again. A folded line is whitespace and becomes one space; any other control character is dropped with a warning.

## Parsers are lenient; warnings report what strict parsing would refuse

Every header-value type parses the way sip-uri does, so the two crates read one way: `HeaderParse::parse` keeps whatever value the input yields, `parse_with_warnings` returns it with the grammar breaches found on the way, and `parse_strict` refuses the first one. A warning names the field, a code, a byte position in the row the caller handed in (the parsed string, or one of the rows or entries a list was built from, with that row's index), and for list types the entry index; it never carries the text, which may be a caller's number. Whether the value still holds what was sent is fixed by the code, not chosen per call site, so one code means the same thing everywhere it is raised. A URI's own warnings pass through with their sip-uri component and code, shifted to the header's positions, and their code's printed name is prefixed so one name identifies one code across both crates.

## Equality is the held form; RFC equivalence is its own trait

`Eq` and `Hash` compare a value as it is held: tokens in the case they were sent, parameters in order and with their quotedness, URIs by sip-uri's identity. Where the held form is canonical it already folds what the RFC folds; parameter names and the tokens of the content-negotiation and security-agreement headers are held lowercased. Comparison under a header's RFC rules (tokens case-insensitive per RFC 3261 section 7.3.1 unless the header's RFC says otherwise, parameters in any order, URIs as RFC 3261 section 19.1.4 compares them) is `HeaderEquivalence`, which delegates every URI to sip-uri's equivalence and exists only where an RFC states the rule; where it is silent, the caller compares the parts its context cares about. Display keeps the case that was sent, since folding it would change what a proxy forwards, and identity never folds by RFC rule, so a later refinement of equivalence cannot change which stored values are equal.

## Lenient parsing fails only where no value exists

`HeaderParse::parse` returns `Err` for input that yields no usable value: empty where the grammar requires content, or a structure the RFC makes the receiver reject outright, such as a second Replaces. Every other breach becomes a warning, so tightening a parser means adding a warning code, never a new rejection. Where a type cannot hold what the input carries, such as a wildcard beside addresses or a Via entry without a host, the parser drops that part under a warning whose kind says data was lost. A list entry that yields no value is such a part, for every list alike, and a list whose grammar needs an entry and has none left is `Err` with the first dropped entry's fault.

## One error type for every header value

Every header-value parser returns the crate's `ParseError`, so nested parsers compose with `?` and a consumer matches one type. A failed URI keeps sip-uri's error as its source rather than a string, and the strict path has one shape: a URI breach under `parse_strict` surfaces as the same non-conformance a header breach does. A framing fault a lookup store reports arrives as the catalog's row error and is carried whole as the source, never mapped onto our fault codes, because the catalog's kinds are open-ended and a mapping would lose the ones added later. Display names the failing layer and leaves the cause to `source()`, so a chain printer shows each cause once. `ParseError` stays `Clone` and `Eq` so callers can compare and keep it; no source it carries may therefore be a boxed foreign error. The conference-info body is XML, not a header value, and keeps its own error, whose source is the XML reader's; header-name catalogs keep theirs, because an unknown name is not a malformed value.

## Stores return one row per occurrence, borrowed and fallible

`extract_header` and every lookup store return one row per header occurrence, never a comma-joined string, because RFC 3261 section 7.3.1 forbids joining the authentication headers; splitting a row into list entries is the accessor's job, and each row is split untrimmed. A store has one required method, the fallible rows lookup, and everything else, the single-value lookup included, derives from it, so two views of one store cannot disagree and a store's decoding failure reaches every caller instead of a value parsed from undecoded text. Rows are borrowed from the store: a store that must unfold or unescape does it once when it is built, never per lookup. A present row that is empty or only whitespace is a blank entry instead of vanishing, and the list reader reports it; a blank entry is never an error, only a list left with no entry where its grammar needs one. Where the grammar admits an empty value, a lone blank value is the empty list; among several blanks none is singled out and each is reported.

Callers pass the canonical name. A store keyed by wire name matches it case-insensitively and through the compact alias, using the catalog's predicate, and returns both spellings in wire order; a store keyed another way translates the name and looks it up directly. A map keyed by wire name returns the rows of every key the name matches, in a fixed key order, since it has no wire order to keep.

## Parameters after a bare addr-spec belong to the header

Without angle brackets, every parameter after the URI is a header parameter (RFC 3261 section 20.10), so a tag on a bare From reaches dialog matching. The split skips a SIP URI's userinfo, where `user` may hold `;`, and Display always brackets the URI, so the parameters stay header parameters when the value is read again.

## Received text is reached by span, not stored

A parsed value's URI, host and parameter values carry a span, a row index and byte range into what the caller handed in, and an error or a warning names the span of the text it concerns instead of the bytes, so a dropped part can still be masked. The value keeps its canonical form, so equality and serde ignore spans, and a builder that changes the value clears them. A span covers the row as held, folds and dropped control characters included. Reading a span says why it found no text, so a caller masking received text never takes an unplaceable span for nothing to mask. Provenance stays in this parser crate: a catalog type holds a canonical value or received text, never both, and indexes, never byte positions.

## Only the header catalog is a stable crate

The header-name catalog and the raw row trait are a crate of their own with a major version, because header names and one row per occurrence are not expected to change: crates exchange them across their public APIs without sharing a parser version, and a consumer would otherwise take a major version with every parser minor. Value types stay in sip-header with their parsers: their shapes are still being settled against real traffic, and a frozen value crate would freeze each open question with it. What every header shares, a name and one row of wire text per occurrence, is frozen in the catalog as a holder that implements the row trait, so a consumer can hand headers across its API and let the caller type them with its own sip-header.

## A header holder stores received text unchecked

The catalog's holders keep names and values exactly as received, control characters and non-token names included. Cleaning received text is the parser's job, where a breach becomes a warning inside a still-usable value; a holder that refused a byte would turn one injected character into a missing header and push every consumer into scrubbing hostile input itself. The holders therefore offer no way to write their text as a header block, and anything sent goes through a typed value, whose constructors refuse what would print as a different value.

## Parsing is spelled through extension traits

Parsing, equivalence and redaction are sealed extension traits a caller imports by name (`HeaderParse`, `ListParse` and their siblings), as sip-uri's `UriParse` is, so the two crates read one way. Should value types later move to a crate of their own, the orphan rule would force traits anyway, and spelling them as traits keeps that move from breaking callers. Every example opens with the exact `use` line it needs, and each value type's rustdoc links the trait that parses it. A token list parses through its own constructors, which take the header, since its case rule comes from the header it holds.

## Lookup stores implement the raw row trait

A store implements `SipHeaderRows` from the catalog and receives every typed accessor from sip-header by blanket impl. A consumer's public API then names only the stable crate, while callers choose their own sip-header version for the accessors.

## Comma-list and repeatable are separate predicates

The catalog says of each header whether its grammar is a comma list, safe to split and join, and separately whether it may occur more than once. The authentication headers may repeat but are not lists, and a store that splits every repeatable header at commas cuts a credential apart. Each classification cites the header's ABNF. Typed lookup takes its row handling from these two predicates rather than from each accessor, and refuses a header whose value type does not match it.

## Redaction masks identity parameters and location references by default

A redacted header hides, besides the URI's user part, the parameters that name a device or user (instance identifiers, GRUUs), Geolocation references, and the addresses a Via carries for the caller's device, since each identifies a caller as surely as a number does. A caller that needs one shown opts in per kind. Redaction is policy and lives in this crate: its configuration owns its data so it is built once and lent to every rendering, every URI a value holds renders through sip-uri's redaction, and a parameter name that policy masks is masked wherever it appears, in a URI or a header. Debug masks credentials and the username beside them, since debug output reaches logs without anyone choosing it.

## Serde converts through private functions

A value's serde mirror and the conversions to and from it are private functions, so every public impl names only types a caller can use, in rustdoc and in rustc's suggestions alike.

## Non-IANA headers are always present

Headers from expired drafts that remain deployed are ordinary catalog entries, with an accessor reporting which registry they come from. A cargo feature would change what parses for every crate in a build as soon as one crate enabled it, and a header later registered by IANA changes only that accessor's answer.

## Catalog serde and ordering use the wire name

A header name serializes as its canonical wire spelling and deserializes from any spelling the parser accepts, so stored data survives a variant rename and matches what a human writes in a config file. It sorts by that spelling too, ignoring case as header names do, so a sorted map or log reads alphabetically and keeps its order when variants are added or moved. Enums built with the catalog's macro get the same serde only when their invocation asks for it, since a feature enabled elsewhere in a build must not add impls to a caller's type. An invocation may ask under a cfg of its own, so a crate whose serde is optional gets it exactly when its own feature is on.

## Error Display never carries the rejected bytes

An error renders a label, the field or position at fault, and the length of the rejected input, never the input itself. A type that keeps the bytes keeps them on a public field, for a caller that decides to print them. A deserializer's error may name a field or key it read, never a value. Display reaches every consumer's `{e}` log line outside whatever redaction the consumer applies, and header values carry credentials, retrieval tokens and caller numbers.

## List-valued types take pre-split entries

Every comma-list type has a `from_entries` constructor beside `parse`, and a problem in one entry surfaces as a warning carrying that entry's index. A caller holding entries a transport already delimited never re-joins them for `parse`: the second split is a guess over boundaries already drawn, and it hides which layer produced a bad entry. Beside it, `from_rows` takes header occurrences and splits each through the path the typed accessors use, so a caller holding rows and a store accessor never disagree on entries or their indexes.
