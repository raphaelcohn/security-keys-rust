// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct AudioControlInterfaceExtraDescriptorParser(pub(crate) AudioProtocol);

impl DescriptorParser for AudioControlInterfaceExtraDescriptorParser
{
	type Descriptor = AudioControlInterfaceExtraDescriptor;
	
	type Error = AudioControlInterfaceExtraDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, device_connection: &DeviceConnection, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		match descriptor_type
		{
			CS_INTERFACE => (),
			
			_ => return Ok(None),
		};
		
		use AudioProtocol::*;
		
		let outcome = match self.0
		{
			Version_1_0 => AudioControlInterfaceExtraDescriptor::parse_descriptor_version_1_0(device_connection, bLength, remaining_bytes)?,
			
			Version_2_0 => AudioControlInterfaceExtraDescriptor::parse_descriptor_version_2_0(device_connection, bLength, remaining_bytes)?,
			
			Version_3_0 => AudioControlInterfaceExtraDescriptor::parse_descriptor_version_3_0(device_connection, bLength, remaining_bytes)?,
			
			Unrecognized(protocol) => AudioControlInterfaceExtraDescriptor::parse_descriptor_version_unrecognized(bLength, remaining_bytes, protocol)?,
		};
		Ok(Some(outcome))
	}
}
