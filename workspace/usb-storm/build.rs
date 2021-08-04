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
#![warn(unused_crate_dependencies)]


//! Build Script.


use std::env::var_os;
use std::path::PathBuf;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::str::FromStr;
use unicode_xid::UnicodeXID;


fn main()
{
	let mut vendors = Vec::with_capacity(u16::MAX as usize);
	read_usb_vendor_names_and_identifiers("extant", false, &mut vendors);
	read_usb_vendor_names_and_identifiers("obsolete", true, &mut vendors);
	write_vendor_implementation(&vendors).unwrap();
}

fn write_vendor_implementation(vendors: &Vec<(String, u16, bool)>) -> io::Result<()>
{
	let mut writer = writer("VendorRegistration.rs");
	writeln!(writer, "impl VendorRegistration\n{{")?;
	write_vendor_registration_implementation_constants(vendors, &mut writer)?;
	write_vendor_registration_implementation_parse(vendors, &mut writer)?;
	writeln!(writer, "}}")?;
	
	Ok(())
}

fn write_vendor_registration_implementation_constants(vendors: &Vec<(String, u16, bool)>, writer: &mut BufWriter<File>) -> io::Result<()>
{
	for &(ref vendor_name, _vendor_identifier, is_obsolete) in vendors.iter()
	{
		let rust_identifier = vendor_name_to_rust_identifier(&vendor_name, is_obsolete);
		let rust_string_literal = vendor_name_to_rust_string_literal(&vendor_name);
		
		writeln!(writer, "\t/// {}.", vendor_name)?;
		writeln!(writer, "\tpub const {}: Self = Self::new({}, {});", rust_identifier, rust_string_literal, is_obsolete)?;
		writeln!(writer)?;
	}
	Ok(())
}

fn write_vendor_registration_implementation_parse(vendors: &Vec<(String, u16, bool)>, writer: &mut BufWriter<File>) -> io::Result<()>
{
	writeln!(writer, "\tfn parse(identifier: VendorIdentifier) -> Option<Self>")?;
	writeln!(writer, "\t{{")?;
	writeln!(writer, "\t\tmatch identifier")?;
	writeln!(writer, "\t\t{{")?;
	for &(ref vendor_name, vendor_identifier, is_obsolete) in vendors.iter()
	{
		let rust_identifier = vendor_name_to_rust_identifier(&vendor_name, is_obsolete);
		writeln!(writer, "\t\t\t{} => Some(Self::{}),", vendor_identifier, rust_identifier)?;
		writeln!(writer)?;
	}
	writeln!(writer, "\t\t\t_ => None")?;
	writeln!(writer, "\t\t}}")?;
	writeln!(writer, "\t}}")?;
	Ok(())
}

fn vendor_name_to_rust_identifier(vendor_name: &str, is_obsolete: bool) -> String
{
	const ObsoletePostfix: &'static str = "_Obsolete";
	let mut rust_identifier = String::with_capacity(1 + vendor_name.len() + ObsoletePostfix.len());
	
	for (index, character) in vendor_name.chars().enumerate()
	{
		if index == 0
		{
			if character.is_xid_start()
			{
				rust_identifier.push(character);
			}
			else if character.is_xid_continue()
			{
				rust_identifier.push('_');
				rust_identifier.push(character);
			}
			else
			{
				rust_identifier.push('_');
			}
		}
		else
		{
			if character.is_xid_continue()
			{
				rust_identifier.push(character);
			}
			else
			{
				rust_identifier.push('_');
			}
		}
	}
	
	if is_obsolete
	{
		rust_identifier.push_str(ObsoletePostfix);
	}
	
	rust_identifier
}

fn vendor_name_to_rust_string_literal(vendor_name: &str) -> String
{
	let mut longest_hash_count = 0;
	let mut current_hash_count = 0;
	for byte in vendor_name.as_bytes()
	{
		let byte = *byte;
		if current_hash_count == 0
		{
			if byte == b'"'
			{
				current_hash_count = 1;
			}
		}
		else
		{
			if byte == b'#'
			{
				current_hash_count += 1;
			}
			else
			{
				let hash_count = current_hash_count;
				if hash_count > longest_hash_count
				{
					longest_hash_count = hash_count;
				}
				current_hash_count = 0;
			}
		}
	}
	
	let mut rust_string_literal = String::with_capacity(2 + vendor_name.len() + 1 + (longest_hash_count * 2));
	rust_string_literal.push('r');
	for _ in 0 .. longest_hash_count
	{
		rust_string_literal.push('#')
	}
	rust_string_literal.push('"');
	rust_string_literal.push_str(vendor_name);
	rust_string_literal.push('"');
	for _ in 0 .. longest_hash_count
	{
		rust_string_literal.push('#')
	}
	rust_string_literal
}

fn read_usb_vendor_names_and_identifiers(file_prefix: &'static str, is_obsolete: bool, vendors: &mut Vec<(String, u16, bool)>)
{
	let mut reader = reader(file_prefix);
	let mut line = 0;
	loop
	{
		let (vendor_name, vendor_identifier) = match read_vendor_name_and_vendor_identifier(&mut reader, file_prefix, &mut line)
		{
			None => break,
			
			Some(x) => x
		};
		vendors.push((vendor_name, vendor_identifier, is_obsolete));
	}
}

fn read_vendor_name_and_vendor_identifier(reader: &mut BufReader<File>, file_prefix: &'static str, line: &mut usize) -> Option<(String, u16)>
{
	let vendor_name = read_line(reader, 32, file_prefix, line)?;
	
	let vendor_identifier_string = match read_line(reader, 5, file_prefix, line)
	{
		Some(line) => line,
		
		None => panic!("Missing vendor identifier in {} on line {}", file_prefix, *line)
	};
	
	let vendor_identifier = match u16::from_str(&vendor_identifier_string)
	{
		Ok(vendor_identifier) => vendor_identifier,
		
		Err(parse_error) => panic!("Could not parse u16 in {} on line {} from value {} because of {}", file_prefix, *line, &vendor_identifier_string, parse_error),
	};
	
	Some((vendor_name, vendor_identifier))
}

fn writer(file_name: &'static str) -> BufWriter<File>
{
	let file_path = out_file_path(file_name);
	let file = File::create(&file_path).map_err(|error| format!("Could not create file path {:?} because of error {}", &file_path, error)).unwrap();
	BufWriter::with_capacity(4096, file)
}

fn out_file_path(file_name: &'static str) -> PathBuf
{
	let out_folder_path = PathBuf::from(var_os("OUT_DIR").expect("OUT_DIR should be set by Cargo"));
	let mut file_path = out_folder_path.to_path_buf();
	file_path.push(file_name);
	file_path
}

fn reader(file_prefix: &'static str) -> BufReader<File>
{
	let file_path = in_file_path(file_prefix);
	let file = File::open(&file_path).map_err(|error| format!("Could not open usb-vendor-names-and-identifiers file path {:?} because of error {}", &file_path, error)).unwrap();
	BufReader::new(file)
}

fn in_file_path(file_prefix: &'static str) -> PathBuf
{
	let cargo_manifest_folder_path = PathBuf::from(var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set by Cargo"));
	let mut file_path = cargo_manifest_folder_path.to_path_buf();
	let file_name = format!("build/{}.usb-vendor-names-and-identifiers.txt", file_prefix);
	println!("cargo:rerun-if-changed={}", file_name);
	file_path.push(file_name);
	file_path
}

fn read_line(reader: &mut BufReader<File>, capacity: usize, file_prefix: &'static str, line: &mut usize) -> Option<String>
{
	let mut line_including_line_feed = String::with_capacity(capacity);
	let result = reader.read_line(&mut line_including_line_feed);
	let current_line = *line;
	*line = current_line + 1;
	match result
	{
		Ok(0) => None,
		
		Ok(_bytes_read) =>
		{
			let line_feed = line_including_line_feed.pop().unwrap();
			assert_eq!(line_feed, '\n', "{} line {} is not new-line terminated", file_prefix, current_line);
			Some(line_including_line_feed)
		}
		
		Err(_) => panic!("Could not read from {} line {} in usb-vendor-names-and-identifiers file", file_prefix, current_line)
	}
}
