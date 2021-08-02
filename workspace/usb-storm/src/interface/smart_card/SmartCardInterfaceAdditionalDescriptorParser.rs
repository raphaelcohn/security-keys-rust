// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(super) struct SmartCardInterfaceAdditionalDescriptorParser
{
	smart_card_protocol: SmartCardProtocol,
	
	expected: u8,
}

impl AdditionalDescriptorParser for SmartCardInterfaceAdditionalDescriptorParser
{
	type Descriptor = SmartCardInterfaceAdditionalDescriptor;
	
	type Error = SmartCardInterfaceAdditionalDescriptorParseError;
	
	#[inline(always)]
	fn no_descriptors_valid() -> bool
	{
		false
	}
	
	#[inline(always)]
	fn multiple_descriptors_valid() -> bool
	{
		false
	}
	
	#[inline(always)]
	fn parse_descriptor(&mut self, descriptor_type: DescriptorType, bytes: &[u8]) -> Result<Option<Self::Descriptor>, Self::Error>
	{
		use SmartCardInterfaceAdditionalDescriptorParseError::*;
		
		if unlikely!(descriptor_type != self.expected)
		{
			return Err(DescriptorIsNeitherOfficialOrVendorSpecific { actual: descriptor_type, expected: self.expected })
		}
		
		if unlikely!(bytes.len() != SmartCardInterfaceAdditionalDescriptor::AdjustedLength)
		{
			return Err(WrongLength)
		}
		
		Ok(Some(SmartCardInterfaceAdditionalDescriptor::parse(self.smart_card_protocol, bytes)?))
	}
}

impl SmartCardInterfaceAdditionalDescriptorParser
{
	#[inline(always)]
	pub(super) const fn new(smart_card_protocol: SmartCardProtocol, bDescriptorType: u8) -> Self
	{
		Self
		{
			smart_card_protocol,
			
			expected: bDescriptorType,
		}
	}
}
