// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![deny(absolute_paths_not_starting_with_crate)]
#![deny(invalid_html_tags)]
#![deny(macro_use_extern_crate)]
#![deny(missing_crate_level_docs)]
#![deny(missing_docs)]
#![deny(pointer_structural_match)]
#![deny(unaligned_references)]
#![deny(unconditional_recursion)]
#![deny(unreachable_patterns)]
#![deny(unused_import_braces)]
#![deny(unused_must_use)]
#![deny(unused_qualifications)]
#![deny(unused_results)]
#![warn(unreachable_pub)]
#![warn(unused_lifetimes)]


//! main.


use self::binary::CommandLineParser;
use security_keys_rust::simple_serializer::SimpleSerializer;
use security_keys_rust::usb::UsbDevice;
use security_keys_rust::usb::errors::UsbError;
use serde::Serialize;


mod binary;


fn main() -> Result<(), UsbError>
{
	let matches = CommandLineParser::parse();
	
	let usb_devices = UsbDevice::usb_devices_try_from()?;
	
	match matches.format()
	{
		CommandLineParser::FormatArgumentValueRustLike =>
		{
			let mut simple_serializer = SimpleSerializer::new_for_standard_out();
			usb_devices.serialize(&mut simple_serializer).expect("Serializing failed");
		}
		
		CommandLineParser::FormatArgumentValueJson => (),
		
		_ => unreachable!(),
	}
	
	Ok(())
}
