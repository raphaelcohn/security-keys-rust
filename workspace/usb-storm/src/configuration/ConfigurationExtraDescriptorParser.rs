// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct ConfigurationExtraDescriptorParser;

impl DescriptorParser for ConfigurationExtraDescriptorParser
{
	type Descriptor = ConfigurationExtraDescriptor;
	
	type Error = ConfigurationExtraDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, string_finder: &StringFinder, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		use ConfigurationExtraDescriptor::*;
		use ConfigurationExtraDescriptorParseError::*;
		
		match descriptor_type
		{
			Self::INTERFACE_ASSOCIATION => match InterfaceAssociationConfigurationExtraDescriptorParser.parse_descriptor(string_finder, bLength, Self::INTERFACE_ASSOCIATION, remaining_bytes)
			{
				Ok(None) => Ok(None),
				
				Ok(Some(Dead)) => Ok(Some(Dead)),
				
				Ok(Some(Alive((descriptor, consumed_length)))) => Ok(Some(Alive((InterfaceAssociation(descriptor), consumed_length)))),
				
				Err(error) => Err(InterfaceAssociationParse(error)),
			}
			
			_ => Ok(None),
		}
	}
}

impl ConfigurationExtraDescriptorParser
{
	const INTERFACE_ASSOCIATION: u8 = 11;
}
