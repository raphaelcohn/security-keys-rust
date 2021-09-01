// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Decoder.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Decoder
{
}

impl Decoder
{
	#[inline(always)]
	fn parse(bLength: u8, remaining_bytes: &[u8]) -> Result<(Self, usize), DecoderParseError>
	{
		use DecoderParseError::*;
		
		const BLength: u8 = X;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<DecoderParseError, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		Ok
			(
				(
					Self
					{
					
					},
					
					descriptor_body_length
				)
			)
	}
}
