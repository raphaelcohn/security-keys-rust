// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct UnsupportedInterfaceAdditionalDescriptorParser;

impl AdditionalDescriptorParser for UnsupportedInterfaceAdditionalDescriptorParser
{
	type Descriptor = UnsupportedInterfaceAdditionalDescriptor;
	
	type Error = Infallible;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, _string_finder: &StringFinder, _bLength: u8, _descriptor_type: DescriptorType, _remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		Ok(None)
	}
}
