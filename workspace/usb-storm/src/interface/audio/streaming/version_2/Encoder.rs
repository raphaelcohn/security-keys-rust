// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Encoder.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Encoder
{
	identifier: EncoderIdentifier,
	
	encoder_type: EncoderType,
	
	bit_rate_control: Control,
	
	quality_control: Control,
	
	vbr_control: Control,
	
	type_control: Control,
	
	underflow_control: Control,
	
	overflow_control: Control,
	
	encoder_error_control: Control,
	
	parameter_controls: ArrayVec<(Control, Option<LocalizedStrings>), { Encoder::NumberOfParameterControls }>,
	
	description: Option<LocalizedStrings>,
}

impl Encoder
{
	const NumberOfParameterControls: usize = 8;
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn identifier(&self) -> EncoderIdentifier
	{
		self.identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn encoder_type(&self) -> EncoderType
	{
		self.encoder_type
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn bit_rate_control(&self) -> Control
	{
		self.bit_rate_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn quality_control(&self) -> Control
	{
		self.quality_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn vbr_control(&self) -> Control
	{
		self.vbr_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn type_control(&self) -> Control
	{
		self.type_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn underflow_control(&self) -> Control
	{
		self.underflow_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn overflow_control(&self) -> Control
	{
		self.overflow_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn encoder_error_control(&self) -> Control
	{
		self.encoder_error_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn parameter_controls(&self) -> &ArrayVec<(Control, Option<LocalizedStrings>), { Encoder::NumberOfParameterControls }>
	{
		&self.parameter_controls
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[inline(always)]
	fn parse(bLength: u8, remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<(Self, usize)>, EncoderParseError>
	{
		use EncoderParseError::*;
		
		const BLength: u8 = 21;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<EncoderParseError, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let bmControls = descriptor_body.u32(descriptor_index::<8>());
		
		Ok
		(
			Alive
			(
				(
					Self
					{
						identifier: descriptor_body.u8(descriptor_index::<3>()),
					
						encoder_type:
						{
							use EncoderType::*;
							match descriptor_body.u8(descriptor_index::<4>())
							{
								0x00 => Undefined,
								
								0x01 => Other,
								
								0x02 => MPEG,
								
								0x03 => AC_3,
								
								0x04 => WMA,
								
								0x05 => DTS,
								
								encoder_type_code @ _ => Unrecognized { encoder_type_code }
							}
						},
						
						bit_rate_control: Control::parse_u32(bmControls, 0, BitRateControlInvalid)?,
						
						quality_control: Control::parse_u32(bmControls, 1, QualityControlInvalid)?,
						
						vbr_control: Control::parse_u32(bmControls, 2, VbrControlInvalid)?,
						
						type_control: Control::parse_u32(bmControls, 3, TypeControlInvalid)?,
						
						underflow_control: Control::parse_u32(bmControls, 4, UnderflowControlInvalid)?,
						
						overflow_control: Control::parse_u32(bmControls, 5, OverflowControlInvalid)?,
						
						encoder_error_control: Control::parse_u32(bmControls, 6, EncoderErrorControlInvalid)?,
						
						parameter_controls:
						{
							let mut parameter_controls = ArrayVec::new_const();
							for index in 0 .. (Self::NumberOfParameterControls as u8)
							{
								let parameter_control = Control::parse_u32(bmControls, (7 + index) as u32, ParameterControlInvalid { index })?;
								let parameter_description = return_ok_if_dead!(string_finder.find_string(descriptor_body.u8(descriptor_index_non_constant((12 + index) as usize))).map_err(|cause| InvalidParameterControlDescriptionString { cause, index })?);
								unsafe { parameter_controls.push_unchecked((parameter_control, parameter_description)); }
							}
							parameter_controls
						},
						
						description: return_ok_if_dead!(string_finder.find_string(descriptor_body.u8(descriptor_index::<20>())).map_err(InvalidDescriptionString)?)
					},
					
					descriptor_body_length
				)
			)
		)
	}
}
