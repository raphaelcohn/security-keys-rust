// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Decoder.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Decoder
{
	identifier: DecoderIdentifier,
	
	details: DecoderDetails,
}

impl Decoder
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn identifier(&self) -> DecoderIdentifier
	{
		self.identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn details(&self) -> &DecoderDetails
	{
		&self.details
	}
	
	#[inline(always)]
	fn parse(bLength: u8, descriptor_body_followed_by_remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<(Self, usize)>, DecoderParseError>
	{
		use DecoderParseError::*;
		
		const MinimumBLength: u8 = 5;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, MinimumBLength>(descriptor_body_followed_by_remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		Ok
		(
			Alive
			(
				(
					Self
					{
						identifier: descriptor_body.u8(descriptor_index::<3>()),
						
						details:
						{
							let decoder_type = descriptor_body.u8(descriptor_index::<4>());
							let dead_or_alive = DecoderDetails::parse(bLength, descriptor_body, decoder_type, string_finder)?;
							return_ok_if_dead!(dead_or_alive)
						},
					},
					
					descriptor_body_length
				)
			)
		)
	}
}
