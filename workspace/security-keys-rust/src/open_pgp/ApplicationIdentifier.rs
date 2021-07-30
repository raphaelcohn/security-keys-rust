// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


pub(crate) struct ApplicationIdentifier
{
	version: u16,

	manufacturer: u16,

	serial: u32,
}

impl ApplicationIdentifier
{
	/// `RID` of FSFE, as per ISO 7816-5; identifies an OpenPGP Application.
	/// See OpenPGP Smart Card Application, Version 3.4.1, Section 4.2.1 Application Identifier (AID).
	pub(crate) const RegisteredApplicationProviderIdentifier: RegisteredApplicationProviderIdentifier = [0xD2, 0x76, 0x00, 0x01, 0x24];
	
	/// `PIX`: Proprietary Application Identifier Extension.
	/// See OpenPGP Smart Card Application, Version 3.4.1, Section 4.2.1 Application Identifier (AID).
	pub(crate) const OpenPgpProprietaryApplicationIdentifierExtension: ProprietaryApplicationIdentifierExtension = 0x01;
	
	const SmartChessProprietaryApplicationIdentifierExtension: ProprietaryApplicationIdentifierExtension = 0x02;
	
	const ReservedProprietaryApplicationIdentifierExtension: ProprietaryApplicationIdentifierExtension = 0xFF;
	
	fn parse(values: &Values) -> Result<Self, ApplicationIdentifierParseError>
	{
		use ApplicationIdentifierParseError::*;
		use Values::*;
		
		let data = match values
		{
			Primitive(data) => data.as_ref(),
			
			Constructed(_) => return Err(ShouldBePrimitive),
		};
		
		const RegisteredApplicationProviderIdentifierLength: usize = size_of::<RegisteredApplicationProviderIdentifier>();
		const ProprietaryApplicationIdentifierExtensionLength: usize = size_of::<ProprietaryApplicationIdentifierExtension>();
		const VersionLength: usize = size_of::<u16>();
		const ManufacturerLength: usize = size_of::<u16>();
		const SerialLength: usize = size_of::<u32>();
		const ReservedLength: usize = 2;
		const ExpectedLength: usize = RegisteredApplicationProviderIdentifierLength + ProprietaryApplicationIdentifierExtensionLength + VersionLength + ManufacturerLength + SerialLength + ReservedLength;
		
		let length = data.len();
		if unlikely!(length != ExpectedLength)
		{
			return Err(WrongLength { length })
		}
		
		let registed_application_provider_identifier: RegisteredApplicationProviderIdentifier = data.get_unchecked_range_safe(0..RegisteredApplicationProviderIdentifierLength).try_into().unwrap();
		if unlikely!(registed_application_provider_identifier != Self::RegisteredApplicationProviderIdentifier)
		{
			return Err(WrongApplicationSelected { registed_application_provider_identifier })
		}
		
		let offset = RegisteredApplicationProviderIdentifierLength;
		let (proprietary_application_identifier_extension, offset) = Self::parse_u8(data, offset);
		match proprietary_application_identifier_extension
		{
			Self::OpenPgpProprietaryApplicationIdentifierExtension => (),
			
			SmartChessProprietaryApplicationIdentifierExtension => return Err(SmartChessProprietaryApplicationUnsupported),
			
			ReservedProprietaryApplicationIdentifierExtension => return Err(ReservedProprietaryApplicationUnsupported),
			
			_ => return Err(UnknownProprietaryApplication { proprietary_application_identifier_extension }),
		};
		
		let (version, offset) = Self::parse_big_endian_u16(data, offset);
		
		let (manufacturer, offset) = Self::parse_big_endian_u16(data, offset);
		
		let (serial, offset) = Self::parse_big_endian_u32(data, offset);
		
		let (reserved, offset) = Self::parse_big_endian_u16(data, offset);
		if unlikely!(reserved != 0x0000)
		{
			return Err(UnknownReservedValue { reserved })
		}
		
		debug_assert_eq!(offset, length);
		
		Ok
		(
			ApplicationIdentifier
			{
				version,
			
				manufacturer,
			
				serial,
			}
		)
	}
	
	#[inline(always)]
	fn parse_u8(data: &[u8], offset: usize) -> (u8, usize)
	{
		(data.get_unchecked_value_safe(offset), offset + size_of::<u8>())
	}
	
	#[inline(always)]
	fn parse_big_endian_u16(data: &[u8], offset: usize) -> (u16, usize)
	{
		const Size: usize = size_of::<u16>();
		let big_endian_bytes: [u8; 2] = data.get_unchecked_range_safe(offset .. (offset + 1)).try_into().unwrap();
		(u16::from_be_bytes(big_endian_bytes), offset + Size)
	}
	
	#[inline(always)]
	fn parse_big_endian_u32(data: &[u8], offset: usize) -> (u32, usize)
	{
		const Size: usize = size_of::<u32>();
		let big_endian_bytes: [u8; 4] = data.get_unchecked_range_safe(offset .. (offset + 3)).try_into().unwrap();
		(u32::from_be_bytes(big_endian_bytes), offset + Size)
	}
}
