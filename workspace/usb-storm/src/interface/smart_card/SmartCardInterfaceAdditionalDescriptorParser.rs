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
	fn parse_descriptor(&mut self, _string_finder: &StringFinder, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		use SmartCardInterfaceAdditionalDescriptorParseError::*;
		
		if unlikely!(descriptor_type != self.expected)
		{
			return Err(DescriptorIsNeitherOfficialOrVendorSpecific { actual: descriptor_type, expected: self.expected })
		}
		
		const MinimumBLength: u8 = SmartCardInterfaceAdditionalDescriptor::Length;
		
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<SmartCardInterfaceAdditionalDescriptorParseError, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		Ok
		(
			Some
			(
				Alive
				(
					(
						SmartCardInterfaceAdditionalDescriptor::parse(self.smart_card_protocol, descriptor_body)?,
						descriptor_body_length
					)
				)
			)
		)
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
