//! Redirect URI candidates for property tests, shared by `redirect_uris.rs` and the cluster tests.
//!
//! Each candidate is assembled from parts chosen to sit on the edges where URL parsers disagree
//! (WHATWG URL Standard in browsers and the `url` crate, Go's `net/url` behind CEL `isURL()`,
//! RFC 3986 in the `http` crate): scheme case and separators, user information, IPv4 in
//! shorthand, hex and out-of-range forms, malformed IPv6 literals, default and oversized ports,
//! non-ASCII, whitespace, backslashes, dot segments and fragments. Most candidates are near
//! misses; enough are valid that the "accepted" side of every property is exercised.

use std::net::Ipv6Addr;

use proptest::prelude::*;

/// A redirect URI candidate.
pub(crate) fn candidate() -> impl Strategy<Value = String> {
    (
        scheme(),
        separator(),
        userinfo(),
        host(),
        port(),
        path(),
        query(),
        fragment(),
    )
        .prop_map(|parts| <[String; 8]>::from(parts).concat())
}

fn just(s: &str) -> BoxedStrategy<String> {
    Just(s.to_owned()).boxed()
}

fn scheme() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => just("https"),
        6 => just("http"),
        1 => just("HTTPS"),
        1 => just("Http"),
        1 => just(""),
        1 => "[a-z][a-z0-9+.-]{0,6}",
    ]
}

fn separator() -> impl Strategy<Value = String> {
    prop_oneof![
        12 => just("://"),
        1 => just(":"),
        1 => just(":/"),
        1 => just(":///"),
        1 => just(":\\\\"),
        1 => just("://\t"),
    ]
}

fn userinfo() -> impl Strategy<Value = String> {
    prop_oneof![
        10 => just(""),
        1 => "[a-z]{0,4}@",
        1 => "[a-z]{1,4}:[a-z]{0,4}@",
        1 => just("127.0.0.1\\@"),
    ]
}

fn host() -> impl Strategy<Value = String> {
    prop_oneof![
        10 => "[a-z0-9-]{1,10}(\\.[a-z0-9-]{1,10}){0,3}",
        2 => "[a-zA-Z0-9-]{1,10}(\\.[a-zA-Z0-9-]{1,10}){0,3}\\.?",
        4 => just("127.0.0.1"),
        4 => just("[::1]"),
        1 => just("localhost"),
        1 => just("127.1"),
        1 => just("0x7f.0.0.1"),
        // Dotted numbers in decimal, octal or hex, in or out of range, one to five parts.
        3 => proptest::collection::vec("[0-9]{1,4}|0[0-7]{1,4}|0x[0-9a-fA-F]{1,3}", 1..=5)
            .prop_map(|parts| parts.join(".")),
        // Valid IPv6, written as Rust (compressed, lowercase) or uppercase.
        2 => any::<[u16; 8]>().prop_map(|segments| format!("[{}]", Ipv6Addr::from(segments))),
        1 => any::<[u16; 8]>()
            .prop_map(|segments| format!("[{}]", Ipv6Addr::from(segments)).to_uppercase()),
        // Anything bracketed: malformed literals, zones, IPv4 suffixes.
        2 => "\\[[0-9a-fA-F:.%]{0,24}\\]",
        1 => "[a-zé-ü]{1,8}\\.example",
        1 => "%[0-9A-F]{2}[a-z]{0,4}\\.example",
        1 => just(""),
    ]
}

fn port() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => just(""),
        1 => just(":"),
        1 => just(":443"),
        1 => just(":80"),
        1 => just(":0"),
        3 => "\\:[0-9]{1,6}",
    ]
}

fn path() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => just(""),
        3 => just("/"),
        1 => just("/./a/../b"),
        6 => proptest::collection::vec("/[a-zA-Z0-9._~!$&'()*+,;=:@-]{0,8}", 1..=3)
            .prop_map(|segments| segments.concat()),
        3 => proptest::collection::vec("/[a-zA-Z0-9._~%:@ <>\"`{}|\\\\^é-]{0,8}", 1..=3)
            .prop_map(|segments| segments.concat()),
    ]
}

fn query() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => just(""),
        2 => "\\?[a-z0-9=&]{0,10}",
        1 => "\\?[ -~é]{0,10}",
    ]
}

fn fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => just(""),
        1 => "#[a-z]{0,4}",
    ]
}
