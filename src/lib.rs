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
//! The IEEE claims trademarks on the names EUI-48 and EUI-64, in which EUI is an
//! abbreviation for Extended Unique Identifier.

#![doc(html_logo_url = "https://www.rust-lang.org/logos/rust-logo-128x128-blk-v2.png",
       html_favicon_url = "https://www.rust-lang.org/favicon.ico",
       html_root_url = "https://doc.rust-lang.org/eui48/")]

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
pub const EUI48LEN: usize = 6;
pub type Eui48 = [u8; EUI48LEN];

/// A 64-bit (8 byte) buffer containing the EUI address
pub const EUI64LEN: usize =  8;
pub type Eui64 = [u8; EUI64LEN];

/// A MAC address (EUI-48)
#[derive(Copy, Clone)]
pub struct MacAddress {
/// The 48-bit number stored in 6 bytes
    eui: Eui48
}

#[derive(Debug)]
pub enum MacAddressFormat {
    Canonical,
    HexString,
    DotNotation,
    Hexadecimal
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum ParseError {
    InvalidLength(usize),
    InvalidCharacter(char, usize)
}

impl MacAddress {
    pub fn new( eui: Eui48 ) -> MacAddress {
        MacAddress { eui: eui }
    }

    /// Returns empty EUI-48 address
    pub fn nil() -> MacAddress {
        MacAddress { eui: [0; EUI48LEN] }
    }

    /// Returns 'ff:ff:ff:ff:ff:ff', a MAC broadcast address
    pub fn broadcast() -> MacAddress {
        MacAddress { eui: [0xFF; EUI48LEN] }
    }

    /// Returns true if the address is '00:00:00:00:00:00'
    pub fn is_nil( &self ) -> bool {
        self.eui.iter().all(|&b| b == 0)
    }

    /// Returns true if the address is 'ff:ff:ff:ff:ff:ff'
    pub fn is_broadcast( &self ) -> bool {
        self.eui.iter().all(|&b| b == 0xFF)
    }

    /// Returns true if bit 1 of Y is 1 in address 'xY:xx:xx:xx:xx:xx'
    pub fn is_unicast( &self ) -> bool {
        self.eui[0] & 0 == 0
    }

    /// Returns true if bit 1 of Y is 1 in address 'xY:xx:xx:xx:xx:xx'
    pub fn is_multicast( &self ) -> bool {
        self.eui[0] & 1 != 0
    }

    /// Returns true if bit 2 of Y is 0 in address 'xY:xx:xx:xx:xx:xx'
    pub fn is_universal( &self ) -> bool {
        self.eui[0] & 1 << 1 == 0
    }

    /// Returns true if bit 2 of Y is 1 in address 'xY:xx:xx:xx:xx:xx'
    pub fn is_local( &self ) -> bool {
        self.eui[0] & 1 << 1 != 0
    }

    /// Returns a String representation in the format '00-00-00-00-00-00'
    pub fn to_canonical( &self ) -> String {
        format!("{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                 self.eui[0], self.eui[1], self.eui[2],
                 self.eui[3], self.eui[4], self.eui[5])
    }

    /// Returns a String representation in the format '00:00:00:00:00:00'
    pub fn to_hex_string( &self ) -> String {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                 self.eui[0], self.eui[1], self.eui[2],
                 self.eui[3], self.eui[4], self.eui[5])
    }

    /// Returns a String representation in the format '0000.0000.0000'
    pub fn to_dot_string( &self ) -> String {
        format!("{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
                 self.eui[0], self.eui[1], self.eui[2],
                 self.eui[3], self.eui[4], self.eui[5])
    }

    /// Returns a String representation in the format '0x000000000000'
    pub fn to_hexadecimal( &self ) -> String {
        format!("0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                 self.eui[0], self.eui[1], self.eui[2],
                 self.eui[3], self.eui[4], self.eui[5])
    }

    /// Returns a String in the format selected by fmt
    pub fn to_string( &self, fmt: MacAddressFormat ) -> String {
        match fmt {
            MacAddressFormat::Canonical    => self.to_canonical(),
            MacAddressFormat::HexString    => self.to_hex_string(),
            MacAddressFormat::DotNotation  => self.to_dot_string(),
            MacAddressFormat::Hexadecimal  => self.to_hexadecimal()
        }
    }

    /// Parses a String representation from any format supported
    pub fn parse_str( s: &str ) -> Result<MacAddress, ParseError> {
        let mut offset = 0;         // Offset into the u8 Eui48 vector
        let mut hn: bool = false;   // Have we seen the high nibble yet?
        let mut eui: Eui48 = [0; EUI48LEN];

        match s.len() {
            14|17   => {},  // The formats are all 12 characters with 2 or 5 delims
            _       => return Err(ParseError::InvalidLength(s.len()))
        }

        for (idx, c) in s.chars().enumerate() {
            if offset >= EUI48LEN {     // We shouln't still be parsing
                return Err(ParseError::InvalidLength(s.len()))
            }

            match c {
                '0'...'9'|'a'...'f'|'A'...'F'   => {
                    match hn {
                        false   =>  { 
                            // We will match '0' and run this even if the format is 0x
                            hn = true;  // Parsed the high nibble
                            eui[offset] = ( c.to_digit(16).unwrap() as u8 ) << 4;
                        },
                        true    => {
                            hn = false; // Parsed the low nibble
                            eui[offset] += c.to_digit(16).unwrap() as u8;
                            offset += 1;
                        }
                    }
                },
                '-'|':'|'.' => { },
                'x'|'X'     => {
                    match idx {
                        1   => {
                            // If idx = 1, we are possibly parsing 0x1234567890ab format
                            // Reset the offset to zero to ignore the first two characters
                            offset = 0;
                            hn = false;
                        },
                        _   => return Err(ParseError::InvalidCharacter(c, idx)) 
                    }
                }
                _           => return Err(ParseError::InvalidCharacter(c, idx))
            }
        }

        if offset == EUI48LEN {         // A correctly parsed value is exactly 6 u8s
            Ok(MacAddress::new(eui))
        }
        else {
            Err(ParseError::InvalidLength(s.len()))     // Something slipped through
        }
    }
}

impl FromStr for MacAddress {
    type Err = ParseError;
    fn from_str( us: &str ) -> Result<MacAddress, ParseError> {
        MacAddress::parse_str(us)
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
        write!(f, "{}", self.to_string(MacAddressFormat::Canonical))
    }
}

impl PartialEq for MacAddress {
    fn eq(&self, other: &MacAddress) -> bool {
        self.eui == other.eui
    }
}

impl Eq for MacAddress {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::InvalidLength(found) =>
                write!(f, "Invalid length; expecting 15 or 18 chars, found {}", found),
             ParseError::InvalidCharacter(found, pos) =>
                write!(f, "Invalid character; found `{}` at offset {}", found, pos),
        }
    }
}

impl Error for ParseError {
    fn description(&self) -> &str {
        "MacAddress parse error"
    }
}

#[cfg(test)]
mod tests {
    use super::{MacAddress, MacAddressFormat, Eui48};

    #[test]
    fn test_new() {
        let eui: Eui48 = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF ];
        let mac = MacAddress::new(eui);

        assert!(mac.eui[0..5] == eui[0..5]);
    }

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
    fn test_is_nil() {
        let nil = MacAddress::nil();
        assert!(nil.is_nil());
    }

    #[test]
    fn test_is_broadcast() {
        let broadcast = MacAddress::broadcast();
        assert!(broadcast.is_broadcast());
    }

    #[test]
    fn test_is_unicast() {
        let mac = MacAddress::parse_str("FE:00:5E:AB:CD:EF").unwrap();
        assert!(mac.is_unicast());
        assert!(MacAddress::nil().is_unicast());
    }

    #[test]
    fn test_is_multicast() {
        let mac = MacAddress::parse_str("01:00:5E:AB:CD:EF").unwrap();
        assert!(mac.is_multicast());
        assert!(MacAddress::broadcast().is_multicast());
    }

    #[test]
    fn test_is_universal() {
        let mac = MacAddress::parse_str("15:24:56:AB:CD:EF").unwrap();
        assert!(mac.is_universal());
    }

    #[test]
    fn test_is_local() {
        let mac = MacAddress::parse_str("16:34:56:AB:CD:EF").unwrap();
        assert!(mac.is_local());
    }

    #[test]
    fn test_to_canonical() {
        let eui: Eui48 = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF ];
        let mac = MacAddress::new(eui);
        let s   = format!("{}", mac);
        assert_eq!(s, mac.to_canonical());
        assert_eq!("12-34-56-ab-cd-ef", mac.to_canonical());
    }

    #[test]
    fn test_to_hex_string() {
        let eui: Eui48 = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF ];
        let mac = MacAddress::new(eui);
        assert_eq!("12:34:56:ab:cd:ef", mac.to_hex_string());
    }

    #[test]
    fn test_to_dot_string() {
        let eui: Eui48 = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF ];
        let mac = MacAddress::new(eui);
        assert_eq!("1234.56ab.cdef", mac.to_dot_string());
    }

    #[test]
    fn test_to_hexadecimal() {
        let eui: Eui48 = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF ];
        let mac = MacAddress::new(eui);
        assert_eq!("0x123456abcdef", mac.to_hexadecimal());
    }

    #[test]
    fn test_to_string() {
        let eui: Eui48 = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF ];
        let mac = MacAddress::new(eui);
        assert_eq!("0x123456abcdef", mac.to_string(MacAddressFormat::Hexadecimal));
        assert_eq!("1234.56ab.cdef", mac.to_string(MacAddressFormat::DotNotation));
        assert_eq!("12:34:56:ab:cd:ef", mac.to_string(MacAddressFormat::HexString));
        assert_eq!("12-34-56-ab-cd-ef", mac.to_string(MacAddressFormat::Canonical));
    }

    #[test]
    fn test_parse_str() {
        use super::ParseError::*;

        assert_eq!("0x123456abcdef",
                   MacAddress::parse_str("0x123456ABCDEF").unwrap().to_hexadecimal());
        assert_eq!("1234.56ab.cdef",
                   MacAddress::parse_str("1234.56AB.CDEF").unwrap().to_dot_string());
        assert_eq!("12:34:56:ab:cd:ef",
                   MacAddress::parse_str("12:34:56:AB:CD:EF").unwrap().to_hex_string());
        assert_eq!("12-34-56-ab-cd-ef",
                   MacAddress::parse_str("12-34-56-AB-CD-EF").unwrap().to_canonical());
        // Test error parsing
        assert_eq!(MacAddress::parse_str(""), Err(InvalidLength(0)));
        assert_eq!(MacAddress::parse_str("0"), Err(InvalidLength(1)));
        assert_eq!(MacAddress::parse_str("123456ABCDEF"), Err(InvalidLength(12)));
        assert_eq!(MacAddress::parse_str("1234567890ABCD"), Err(InvalidLength(14)));
        assert_eq!(MacAddress::parse_str("1234567890ABCDEF"), Err(InvalidLength(16)));
        assert_eq!(MacAddress::parse_str("01234567890ABCDEF"), Err(InvalidLength(17)));
        assert_eq!(MacAddress::parse_str("0x1234567890A"), Err(InvalidLength(13)));
        assert_eq!(MacAddress::parse_str("0x1234567890ABCDE"), Err(InvalidLength(17)));
        assert_eq!(MacAddress::parse_str("0x00:00:00:00:"), Err(InvalidLength(14)));
        assert_eq!(MacAddress::parse_str("0x00:00:00:00:00:"), Err(InvalidLength(17)));
        assert_eq!(MacAddress::parse_str("::::::::::::::"), Err(InvalidLength(14)));
        assert_eq!(MacAddress::parse_str(":::::::::::::::::"), Err(InvalidLength(17)));
        assert_eq!(MacAddress::parse_str("0x0x0x0x0x0x0x"), Err(InvalidCharacter('x', 3)));
        assert_eq!(MacAddress::parse_str("!0x00000000000"), Err(InvalidCharacter('!', 0)));
        assert_eq!(MacAddress::parse_str("0x00000000000!"), Err(InvalidCharacter('!', 13)));
    }

    #[test]
    fn test_compare() {
        let m1 = MacAddress::nil();
        let m2 = MacAddress::broadcast();
        assert!(m1 == m1);
        assert!(m2 == m2);
        assert!(m1 != m2);
        assert!(m2 != m1);
    }

    #[test]
    fn test_clone() {
        let m1 = MacAddress::parse_str("12:34:56:AB:CD:EF").unwrap();
        let m2 = m1.clone();
        assert!(m1 == m1);
        assert!(m2 == m2);
        assert!(m1 == m2);
        assert!(m2 == m1);
    }

}
