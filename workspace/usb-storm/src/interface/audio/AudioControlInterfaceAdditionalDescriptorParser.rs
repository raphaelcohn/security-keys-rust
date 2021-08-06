// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(super) struct AudioControlInterfaceAdditionalDescriptorParser;

impl AdditionalDescriptorParser for AudioControlInterfaceAdditionalDescriptorParser
{
	type Descriptor = AudioControlInterfaceAdditionalDescriptor;
	
	type Error = AudioControlInterfaceAdditionalDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<(Self::Descriptor, usize)>, Self::Error>
	{
		use AudioControlInterfaceAdditionalDescriptorParseError::*;
		
		match descriptor_type
		{
			CS_INTERFACE => (),
			
			_ => return Ok(None),
		};
		
		const MinimumBLength: usize = XXXX;
		let (descriptor_body, descriptor_body_length) = Self::verify_remaining_bytes::<AudioControlInterfaceAdditionalDescriptorParseError, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
	}
}
