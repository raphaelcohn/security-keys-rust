// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio format Type I extended details.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version2AudioFormatExtendedTypeIIDetails
{
	header_length: u8,
	
	side_band_protocol: SideBandProtocol,
}

impl Version2AudioFormatExtendedTypeIIDetails
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn header_length(&self) -> u8
	{
		self.header_length
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn side_band_protocol(&self) -> SideBandProtocol
	{
		self.side_band_protocol
	}
	
	#[inline(always)]
	fn parse(subsequent_format_type_descriptor_body: &[u8]) -> Self
	{
		Self
		{
			header_length: subsequent_format_type_descriptor_body.u8(descriptor_index::<8>()),
			
			side_band_protocol: SideBandProtocol::parse(subsequent_format_type_descriptor_body.u8(descriptor_index::<9>()))
		}
	}
}
