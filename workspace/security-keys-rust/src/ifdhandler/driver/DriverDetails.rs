// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
struct DriverDetails
{
	capabilities: BitFlags<DriverCapabilities>,

	usb_details: UsbDeviceInformationDatabase<String>,
}

impl DriverDetails
{
	#[inline(always)]
	fn parse_remaining_info_plist_fields(info_plist: &Dictionary) -> Result<Self, LoadDriverError>
	{
		use LoadDriverError::*;
		
		let capabilities = Self::parse_capabilities(info_plist)?;
		
		let vendor_identifiers = Self::get_array(&info_plist, "ifdVendorID", MissingVendorIdentifierArray)?;
		let product_identifiers = Self::get_array(&info_plist, "ifdProductID", MissingProductIdentifierArray)?;
		let friendly_names = Self::get_array(&info_plist, "ifdFriendlyName", MissingFriendlyNameArray)?;
		
		Self::array_lengths_match(vendor_identifiers, product_identifiers, ProductIdentifiersArrayLengthDiffersToVendorIdentifiersArray)?;
		Self::array_lengths_match(vendor_identifiers, friendly_names, FriendlyNamesArrayLengthDiffersToVendorIdentifiersArray)?;
		
		let length = vendor_identifiers.len();
		let mut usb_details = Self::new_hash_map(length)?;
		for index in 0 .. length
		{
			let vendor_identifier = Self::convert_hexadecimal(Self::get_array_string(vendor_identifiers, index, VendorIdentifierIsNotAString)?, VendorIdentifierStringIsNot6Bytes, VendorIdentifierIsNotHexadecimal)?;
			let product_identifier = Self::convert_hexadecimal(Self::get_array_string(product_identifiers, index, ProductIdentifierIsNotAString)?, ProductIdentifierStringIsNot6Bytes, ProductIdentifierIsNotHexadecimal)?;
			let friendly_name = Self::get_array_string(friendly_names, index, FriendlyNameIsNotAString)?;
			
			let _ = usb_details.insert((vendor_identifier, product_identifier), friendly_name.to_string());
		}
		Ok
		(
			Self
			{
				capabilities,
				
				usb_details: UsbDeviceInformationDatabase::from_hash_map(usb_details)
			}
		)
	}
	
	#[inline(always)]
	fn new_hash_map(length: usize) -> Result<HashMap<(UsbVendorIdentifier, UsbProductIdentifier), String>, LoadDriverError>
	{
		let mut usb_details = HashMap::new();
		usb_details.try_reserve(length).map_err(LoadDriverError::CouldNotAllocateMemoryForUsbDetails)?;
		Ok(usb_details)
	}
	
	#[inline(always)]
	fn parse_capabilities(info_plist: &Dictionary) -> Result<BitFlags<DriverCapabilities>, LoadDriverError>
	{
		use LoadDriverError::*;
		
		let capabilities_string = dictionary_get_string(info_plist, "ifdCapabilities", MissingCapabilitiesString)?;
		let capabilities_u32 = Self::convert_hexadecimal(capabilities_string, CapabilitiesIsNot10Bytes, CapabilitiesIsNotHexadecimal)?;
		BitFlags::from_bits(capabilities_u32).map_err(CapabilitiesBitFlagsAreUnknown)
	}
	
	#[inline(always)]
	fn get_array<'a>(info_plist: &'a Dictionary, key: &str, error: LoadDriverError) -> Result<&'a [Value], LoadDriverError>
	{
		match info_plist.get(key)
		{
			Some(&Value::Array(ref array)) => Ok(array.as_slice()),
			
			_ => Err(error),
		}
	}
	
	#[inline(always)]
	fn array_lengths_match(array1: &[Value], array2: &[Value], error: LoadDriverError) -> Result<(), LoadDriverError>
	{
		if likely!(array1.len() == array2.len())
		{
			Ok(())
		}
		else
		{
			Err(error)
		}
	}
	
	#[inline(always)]
	fn get_array_string(array: &[Value], index: usize, error: LoadDriverError) -> Result<&str, LoadDriverError>
	{
		match array.get_unchecked_safe(index)
		{
			&Value::String(ref string) => Ok(string.as_str()),
			
			_ => Err(error),
		}
	}
	
	#[inline(always)]
	fn convert_hexadecimal<T: ParseNumber>(value: &str, error_length: LoadDriverError, error_prefix: impl FnOnce(ParseNumberError) -> LoadDriverError) -> Result<T, LoadDriverError>
	{
		/// `0x`.
		const PrefixLength: usize = 2;
		
		// 6 for an u16.
		// 10 for an u32.
		// Is not a constant because Rust does not permit the use of generic parameters in constants, yet.
		let Length: usize = PrefixLength + (size_of::<T>() * 2);
		
		if unlikely!(value.len() != Length)
		{
			return Err(error_length)
		}
		
		T::parse_hexadecimal_number_upper_or_lower_case_with_0x_prefix(value.as_bytes()).map_err(error_prefix)
	}
}
