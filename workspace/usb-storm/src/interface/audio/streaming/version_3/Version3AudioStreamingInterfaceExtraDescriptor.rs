// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Class-specific AS interface descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version3AudioStreamingInterfaceExtraDescriptor
{
	General
	{
		terminal_link: Option<TerminalEntityIdentifier>,
	},
}

impl Version3AudioStreamingInterfaceExtraDescriptor
{
	#[inline(always)]
	pub(super) fn parse(bLength: u8, remaining_bytes: &[u8]) -> Result<(Self, usize), Version3AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use Version3AudioStreamingInterfaceExtraDescriptorParseError::*;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<Version3AudioStreamingInterfaceExtraDescriptorParseError, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		Ok
		(
			(
				Version3AudioStreamingInterfaceExtraDescriptor::General
				{
					terminal_link: descriptor_body.optional_non_zero_u8(descriptor_index::<3>())
				},
				
				descriptor_body_length,
			)
		)
	}
}
