macaddress
====

[![Build Status](https://travis-ci.org/rust-lang-nursery/macaddress.svg?branch=master)](https://travis-ci.org/rust-lang-nursery/macaddress)
[![](http://meritbadge.herokuapp.com/macaddress)](https://crates.io/crates/macaddress)

A Rust library to represent and parse IEEE MAC-48 media access control addresses.

[Documentation](https://doc.rust-lang.org/macaddress)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]

macaddress. = "0.1"
```

and this to your crate root:

```rust
extern crate macaddress;
```

## Examples

To create a new random (V4) UUID and print it out in hexadecimal form:

```rust
use macaddress::Uuid;

fn main() {
    let my_macaddress = Macaddress::new();
		    println!("{}", my_macaddress);
				}
				```


## References
[Wikipedia: MAC address](https://en.wikipedia.org/wiki/MAC_address)

