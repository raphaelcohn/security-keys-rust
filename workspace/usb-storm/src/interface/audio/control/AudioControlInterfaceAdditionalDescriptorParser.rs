// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(super) struct AudioControlInterfaceAdditionalDescriptorParser(AudioProtocol);

impl AdditionalDescriptorParser for AudioControlInterfaceAdditionalDescriptorParser
{
	type Descriptor = AudioControlInterfaceAdditionalDescriptor;
	
	type Error = AudioControlInterfaceAdditionalDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, _string_finder: &StringFinder, string_finder: &StringFinder, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		match descriptor_type
		{
			Self::CS_INTERFACE => (),
			
			_ => return Ok(None),
		};
		
		use AudioProtocol::*;
		
		let outcome = match self.0
		{
			Version_1_0 => AudioControlInterfaceAdditionalDescriptor::parse_descriptor_version_1_0(string_finder, bLength, remaining_bytes),
			
			Version_2_0 => AudioControlInterfaceAdditionalDescriptor::parse_descriptor_version_2_0(string_finder, bLength, remaining_bytes),
			
			Version_3_0 => AudioControlInterfaceAdditionalDescriptor::parse_descriptor_version_3_0(string_finder, bLength, remaining_bytes),
			
			Unrecognized(protocol) => AudioControlInterfaceAdditionalDescriptor::parse_descriptor_version_unrecognized(bLength, remaining_bytes, protocol),
		}?;
		Ok(Some(outcome))
	}
}

impl AudioControlInterfaceAdditionalDescriptorParser
{
	const CS_UNDEFINED: u8 = 0x20;
	
	const CS_DEVICE: u8 = 0x21;
	
	const CS_CONFIGURATION: u8 = 0x22;
	
	const CS_STRING: u8 = 0x23;
	
	const CS_INTERFACE: u8 = 0x24;
	
	const CS_ENDPOINT: u8 = 0x25;
	
	/// Only defined for version 3.0.
	const CS_CLUSTER: u8 = 0x26;
}
