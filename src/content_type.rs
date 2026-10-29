//! `Content-Type` (RFC 3261 section 20.15).
//!
//! `media-type = m-type SLASH m-subtype *(SEMI m-parameter)` (section
//! 25.1), compact form `c`. Type and subtype are held lowercased, as the
//! content-negotiation tokens are; parameters are held as received, so a
//! multipart `boundary`, compared as written (RFC 2046), prints back byte
//! for byte.
//!
//! The type/subtype split is the one Accept uses, shared rather than
//! copied. The parameters are not: Accept reads `q` as a qvalue, while in a
//! media-type `q` is an ordinary parameter, so they go through the generic
//! header-parameter reader. A `*` type or subtype, legal only in an Accept
//! range, is kept under `InvalidToken`.
