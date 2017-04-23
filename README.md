eui48
====

[![Build Status](https://travis-ci.org/rust-lang-nursery/eui48.svg?branch=master)](https://travis-ci.org/rust-lang-nursery/eui48)
[![](http://meritbadge.herokuapp.com/eui48)](https://crates.io/crates/eui48)

A Rust library to represent and parse IEEE EUI-48 also known as MAC-48 media access control addresses. The IEEE claims trademarks on the names EUI-48 and EUI-64, in which EUI is an abbreviation for Extended Unique Identifier.


[Documentation](https://doc.rust-lang.org/eui48)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]

eui48 = "0.1"
```

and this to your crate root:

```rust
extern crate eui48;
```

## Examples

To create a new MAC address and print it out in canonical form:

```rust
extern crate eui48;
use eui48::{MacAddress, Eui48};

fn main() {
	let eui: Eui48 = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF ];
	let mac = MacAddress::new( eui );

	println!("{}", mac.to_canonical());
	println!("{}", mac.to_hex_string());
	println!("{}", mac.to_dot_string());
	println!("{}", mac.to_hexadecimal());

	let mac = MacAddress::parse_str( "01-02-03-0A-0b-0f" ).expect("Parse error {}");
	let mac = MacAddress::parse_str( "01:02:03:0A:0b:0f" ).expect("Parse error {}");
	let mac = MacAddress::parse_str( "0102.030A.0b0f" ).expect("Parse error {}");
	let mac = MacAddress::parse_str( "0x1234567890ab" ).expect("Parse error {}");
}
```

## References
[Wikipedia: MAC address](https://en.wikipedia.org/wiki/MAC_address)

## Authors
0.1 - Andrew Baumhauer
0.2 - rlcomstock3 - Added support for btree keys
