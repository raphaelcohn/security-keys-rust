// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(super) struct InterfaceAssociationConfigurationExtraDescriptorParser;

impl DescriptorParser for InterfaceAssociationConfigurationExtraDescriptorParser
{
	type Descriptor = InterfaceAssociationConfigurationExtraDescriptor;
	
	type Error = InterfaceAssociationConfigurationExtraDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, device_connection: &DeviceConnection, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		debug_assert_eq!(descriptor_type, ConfigurationExtraDescriptorParser::INTERFACE_ASSOCIATION);
		
		use InterfaceAssociationConfigurationExtraDescriptorParseError::*;
		
		const MinimumBLength: u8 = 8;
		
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let descriptor = match InterfaceAssociationConfigurationExtraDescriptor::parse(descriptor_body, device_connection)?
		{
			Dead => return Ok(Some(Dead)),
			
			Alive(descriptor) => descriptor,
		};
		
		Ok
		(
			Some
			(
				Alive
				(
					(
						descriptor,
						descriptor_body_length
					)
				)
			)
		)
	}
}
