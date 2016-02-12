eui48
====

[![Build Status](https://travis-ci.org/rust-lang-nursery/eui48.svg?branch=master)](https://travis-ci.org/rust-lang-nursery/eui48)
[![](http://meritbadge.herokuapp.com/eui48)](https://crates.io/crates/eui48)

A Rust library to represent and parse IEEE EUI-48 also known as MAC-48 media access control addresses.
The IEEE claims trademarks on the names EUI-48 and EUI-64, in which EUI is an abbreviation for Extended Unique Identifier.


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
use eui48::MacAddress;

fn main() {
    let mac = MacAddress::new();
		    println!("{}", mac);
				}
				```


## References
[Wikipedia: MAC address](https://en.wikipedia.org/wiki/MAC_address)

