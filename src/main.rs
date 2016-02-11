extern crate macaddress;
use macaddress::{MacAddress, Eui48};

fn main() {
    let eui: Eui48 = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF ];
    let mac = MacAddress::new( eui ).unwrap();

    println!("{}", mac.to_canonical());
    println!("{}", mac.to_hex_string());
    println!("{}", mac.to_dot_string());
    println!("{}", mac.to_hexadecimal());
}
