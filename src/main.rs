extern crate macaddress;
use macaddress::{MacAddress, Eui48};

fn main() {
    let eui: Eui48 = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF ];
    let mac = MacAddress::new( eui );

    println!("{}", mac.to_canonical());
    println!("{}", mac.to_hex_string());
    println!("{}", mac.to_dot_string());
    println!("{}", mac.to_hexadecimal());

    let mac = MacAddress::parse_str( "01:02:03:0A:0b:0f" ).expect("Parse error {}");
    println!("{}", mac.to_canonical());
    println!("{}", mac.to_hex_string());
    println!("{}", mac.to_dot_string());
    println!("{}", mac.to_hexadecimal());

    let mac = MacAddress::parse_str( "0x1234567890ab" ).expect("Parse error {}");
    println!("{}", mac.to_canonical());
    println!("{}", mac.to_hex_string());
    println!("{}", mac.to_dot_string());
    println!("{}", mac.to_hexadecimal());
}
