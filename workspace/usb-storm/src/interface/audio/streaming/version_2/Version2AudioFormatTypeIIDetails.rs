// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio format Type II details.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version2AudioFormatTypeIIDetails
{
	maximum_bit_rate_in_kilobits_per_second: u16,
	
	samples_per_frame: u16,
	
	extended: Option<Version2AudioFormatExtendedTypeIIDetails>,
}

impl Version2AudioFormatTypeIIDetails
{
	#[inline(always)]
	pub fn extended(&self) -> Option<&Version2AudioFormatExtendedTypeIIDetails>
	{
		self.extended.as_ref()
	}
	
	#[inline(always)]
	pub const fn maximum_bit_rate_in_kilobits_per_second(&self) -> u16
	{
		self.maximum_bit_rate_in_kilobits_per_second
	}
	
	#[inline(always)]
	pub const fn samples_per_frame(&self) -> u16
	{
		self.samples_per_frame
	}
	
	#[inline(always)]
	fn parse_unextended(subsequent_format_type_descriptor_body: &[u8]) -> Result<Self, FormatTypeDescriptorParseError>
	{
		Self::parse_common(subsequent_format_type_descriptor_body, None)
	}
	
	#[inline(always)]
	fn parse_extended(subsequent_format_type_descriptor_body: &[u8]) -> Result<Self, FormatTypeDescriptorParseError>
	{
		let extended = Version2AudioFormatExtendedTypeIIDetails::parse(subsequent_format_type_descriptor_body);
		Self::parse_common(subsequent_format_type_descriptor_body, Some(extended))
	}
	
	#[inline(always)]
	fn parse_common(subsequent_format_type_descriptor_body: &[u8], extended: Option<Version2AudioFormatExtendedTypeIIDetails>) -> Result<Self, FormatTypeDescriptorParseError>
	{
		Ok
		(
			Self
			{
				maximum_bit_rate_in_kilobits_per_second: subsequent_format_type_descriptor_body.u16(descriptor_index::<4>()),
				
				samples_per_frame: subsequent_format_type_descriptor_body.u16(descriptor_index::<6>()),
			
				extended,
			}
		)
	}
}
