// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio format details.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2AudioFormatDetails
{
	/// Undefined.
	Undefined
	{
		/// A bit map.
		formats: u32,
	},

	#[allow(missing_docs)]
	TypeI
	{
		formats: WrappedBitFlags<Version2AudioFormatTypeI>,
		
		details: Version2AudioFormatTypeIDetails,
	},

	#[allow(missing_docs)]
	TypeII
	{
		formats: WrappedBitFlags<Version2AudioFormatTypeII>,
		
		details: Version2AudioFormatTypeIIDetails,
	},

	#[allow(missing_docs)]
	TypeIII
	{
		formats: WrappedBitFlags<Version2AudioFormatTypeIII>,
		
		details: Version2AudioFormatTypeIIIDetails,
	},
	
	#[allow(missing_docs)]
	TypeIV
	{
		formats: WrappedBitFlags<Version2AudioFormatTypeIV>,
	}
}

impl Version2AudioFormatDetails
{
	#[inline(always)]
	fn parse(general_format_type: u8, formats_bit_map: u32, subsequent_format_type_descriptor_body: &[u8], bLength: u8) -> Result<Self, FormatTypeDescriptorParseError>
	{
		use FormatTypeDescriptorParseError::*;
		use Version2AudioFormatDetails::*;
		
		Ok
		(
			match general_format_type
			{
				0x00 => Undefined
				{
					formats: formats_bit_map
				},
				
				0x01 =>
				{
					if unlikely!(bLength < 6)
					{
						return Err(FormatTypeIBLengthLessThanMinimum)
					}
					
					TypeI
					{
						formats: Version2AudioFormatTypeI::parse(formats_bit_map),
					
						details: Version2AudioFormatTypeIDetails::parse_unextended(subsequent_format_type_descriptor_body)?,
					}
				},
				
				0x02 =>
				{
					if unlikely!(bLength < 8)
					{
						return Err(FormatTypeIIBLengthLessThanMinimum)
					}
					
					TypeII
					{
						formats: Version2AudioFormatTypeII::parse(formats_bit_map),
						
						details: Version2AudioFormatTypeIIDetails::parse_unextended(subsequent_format_type_descriptor_body)?,
					}
				},
				
				0x03 =>
				{
					if unlikely!(bLength < 6)
					{
						return Err(FormatTypeIIIBLengthLessThanMinimum)
					}
					
					TypeIII
					{
						formats: Version2AudioFormatTypeIII::parse(formats_bit_map),
						
						details: Version2AudioFormatTypeIIIDetails::parse_unextended(subsequent_format_type_descriptor_body)?,
					}
				},
				
				0x04 => TypeIV
				{
					formats: Version2AudioFormatTypeIV::parse(formats_bit_map),
				},
				
				0x81 =>
				{
					if unlikely!(bLength < 9)
					{
						return Err(FormatExtendedTypeIBLengthLessThanMinimum)
					}
					
					TypeI
					{
						formats: Version2AudioFormatTypeI::parse(formats_bit_map),
						
						details: Version2AudioFormatTypeIDetails::parse_extended(subsequent_format_type_descriptor_body)?,
					}
				},
				
				0x82 =>
				{
					if unlikely!(bLength < 10)
					{
						return Err(FormatExtendedTypeIIBLengthLessThanMinimum)
					}
					
					TypeII
					{
						formats: Version2AudioFormatTypeII::parse(formats_bit_map),
						
						details: Version2AudioFormatTypeIIDetails::parse_extended(subsequent_format_type_descriptor_body)?,
					}
				},
				
				0x83 =>
				{
					if unlikely!(bLength < 8)
					{
						return Err(FormatTypeIIIExtendedBLengthLessThanMinimum)
					}
					
					TypeIII
					{
						formats: Version2AudioFormatTypeIII::parse(formats_bit_map),
						
						details: Version2AudioFormatTypeIIIDetails::parse_extended(subsequent_format_type_descriptor_body)?,
					}
				},
				
				bFormatType @ _ => return Err(UnrecognizedFormatTypeCode { bFormatType })
			}
		)
	}
}
