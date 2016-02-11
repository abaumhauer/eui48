// Copyright 2013-2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Represent and parse IEEE EUI-48 Media Access Control addresses

#![doc(html_logo_url = "https://www.rust-lang.org/logos/rust-logo-128x128-blk-v2.png",
       html_favicon_url = "https://www.rust-lang.org/favicon.ico",
       html_root_url = "https://doc.rust-lang.org/macaddress/")]

#![cfg_attr(test, deny(warnings))]

#![allow(unused_imports)]
extern crate rustc_serialize;
#[cfg(feature = "serde")]
extern crate serde;

use std::default::Default;
use std::error::Error;
use std::fmt;
use std::hash;
use std::iter::repeat;
use std::mem::{transmute, transmute_copy};
use std::str::FromStr;

use rustc_serialize::{Encoder, Encodable, Decoder, Decodable};
#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// A 48-bit (6 byte) buffer containing the EUI address
pub type Eui48 = [u8; 6];

/// A 64-bit (8 byte) buffer containing the EUI address
pub type Eui64 = [u8; 8];

/// A MAC address (EUI-48)
#[derive(Copy, Clone)]
pub struct MacAddress {
/// The 48-bit number stored in 6 bytes
    eui: Eui48
}

pub enum MacAddressFormat {
    Canonical    = 1,
    HexString    = 2,
    DotNotation  = 3,
    Hexadecimal  = 4
}

impl MacAddress {
    pub fn new( eui: Eui48 ) -> Option<MacAddress> {
        Some(MacAddress { eui: eui })
    }

    /// Returns empty EUI-48 address
    pub fn nil() -> MacAddress {
        MacAddress { eui: [0; 6] }
    }

    pub fn broadcast() -> MacAddress {
        MacAddress { eui: [0xFF; 6] }
    }

    pub fn is_nil( &self ) -> bool {
        self.eui.iter().all(|&b| b == 0)
    }

    pub fn is_broadcast( &self ) -> bool {
        self.eui.iter().all(|&b| b == 0xFF)
    }

    pub fn to_canonical( &self ) -> String {
        format!("{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                 self.eui[0], self.eui[1], self.eui[2],
                 self.eui[3], self.eui[4], self.eui[5])
    }

    pub fn to_hex_string( &self ) -> String {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                 self.eui[0], self.eui[1], self.eui[2],
                 self.eui[3], self.eui[4], self.eui[5])
    }

    pub fn to_dot_string( &self ) -> String {
        format!("{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
                 self.eui[0], self.eui[1], self.eui[2],
                 self.eui[3], self.eui[4], self.eui[5])
    }

    pub fn to_hexadecimal( &self ) -> String {
        format!("0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                 self.eui[0], self.eui[1], self.eui[2],
                 self.eui[3], self.eui[4], self.eui[5])
    }

    pub fn to_string( &self, fmt: MacAddressFormat ) -> String {
        match fmt {
            MacAddressFormat::Canonical    => self.to_canonical(),
            MacAddressFormat::HexString    => self.to_hex_string(),
            MacAddressFormat::DotNotation  => self.to_dot_string(),
            MacAddressFormat::Hexadecimal  => self.to_hexadecimal()
        }
    }
}

impl Default for MacAddress {
    fn default() -> MacAddress {
        MacAddress::nil()
    }
}

impl fmt::Debug for MacAddress {
    fn fmt( &self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MacAddress(\"{}\")", self.to_string(MacAddressFormat::HexString))
    }
}

impl fmt::Display for MacAddress {
    fn fmt( &self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string(MacAddressFormat::HexString))
    }
}

#[cfg(test)]
mod tests {
    use super::{MacAddress, MacAddressBytes};

     #[test]
     fn test_nil() {
        let nil = MacAddress::nil();
        let not_nil = MacAddress::broadcast();

        assert!(nil.is_nil());
        assert!(!not_nil.is_nil());
     }

     #[test]
     fn test_broadcast() {
        let broadcast = MacAddress::broadcast();
        let not_broadcast = MacAddress::nil();

        assert!(broadcast.is_broadcast());
        assert!(!not_broadcast.is_broadcast());
     }

     #[test]
     fn test_new() {
        let eui: MacAddressBytes = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF ];
        let mac = MacAddress::new(eui).unwrap();
        println!("{:?}", mac.eui);
        assert!(mac.eui[0..5] == eui[0..5]);
     }
}
