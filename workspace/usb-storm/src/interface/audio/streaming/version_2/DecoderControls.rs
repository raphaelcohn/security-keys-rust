// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Decoder controls.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecoderControls
{
	underflow_control: Control,
	
	overflow_control: Control,
	
	decoder_error_control: Control,
}

impl DecoderControls
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn underflow_control(self) -> Control
	{
		self.underflow_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn overflow_control(self) -> Control
	{
		self.overflow_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn decoder_error_control(self) -> Control
	{
		self.decoder_error_control
	}
	
	#[inline(always)]
	fn parse<const index: usize, const first_control_index: u8>(descriptor_body: &[u8]) -> Result<Self, DecoderControlParseError>
	{
		use DecoderControlParseError::*;
		
		let bmControls = descriptor_body.u8(descriptor_index::<index>());
		Ok
		(
			Self
			{
				underflow_control: Control::parse_u8(bmControls, first_control_index, UnderflowControlInvalid)?,
				
				overflow_control: Control::parse_u8(bmControls, first_control_index + 1, OverflowControlInvalid)?,
				
				decoder_error_control: Control::parse_u8(bmControls, first_control_index + 2, DecoderErrorControlInvalid)?,
			}
		)
	}
}
