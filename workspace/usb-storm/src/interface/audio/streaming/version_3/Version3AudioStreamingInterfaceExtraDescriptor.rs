// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Class-specific AS interface descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version3AudioStreamingInterfaceExtraDescriptor
{
	#[allow(missing_docs)]
	General(General),
	
	#[allow(missing_docs)]
	ValidSamplingFrequencyRange(FrequencyRange),
}

impl Version3AudioStreamingInterfaceExtraDescriptor
{
	pub(super) const AS_DESCRIPTOR_UNDEFINED: u8 = 0x00;
	
	pub(super) const AS_GENERAL: u8 = 0x01;
	
	pub(super) const AS_VALID_FREQ_RANGE: u8 = 0x02;
	
	#[inline(always)]
	pub(super) fn parse_general(bLength: u8, remaining_bytes: &[u8]) -> Result<Self, Version3AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use GeneralControlsParseError::*;
		use GeneralParseError::*;
		
		Ok(Version3AudioStreamingInterfaceExtraDescriptor::General(General::parse(bLength, remaining_bytes).map_err(Version3AudioStreamingInterfaceExtraDescriptorParseError::GeneralParse)?))
	}
	
	#[inline(always)]
	pub(super) fn parse_valid_sampling_frequency_range(bLength: u8, remaining_bytes: &[u8]) -> Result<Self, Version3AudioStreamingInterfaceExtraDescriptorParseError>
	{
		Ok(Version3AudioStreamingInterfaceExtraDescriptor::ValidSamplingFrequencyRange(FrequencyRange::parse(bLength, remaining_bytes).map_err(Version3AudioStreamingInterfaceExtraDescriptorParseError::ValidSamplingFrequencyRangeParse)?))
	}
}
