// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio channel feature controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version2AudioChannelFeatureControls
{
	mute_control: Control,

	volume_control: Control,

	bass_control: Control,

	mid_control: Control,

	treble_control: Control,

	graphic_equalizer_control: Control,

	automatic_gain_control: Control,

	delay_control: Control,

	bass_boost_control: Control,

	loudness_control: Control,

	input_gain_control: Control,

	input_gain_pad_control: Control,

	phase_inverter_control: Control,

	underflow_control: Control,

	overflow_control: Control,
}

impl Version2AudioChannelFeatureControls
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn mute_control(&self) -> Control
	{
		self.mute_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn volume_control(&self) -> Control
	{
		self.volume_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn bass_control(&self) -> Control
	{
		self.bass_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn mid_control(&self) -> Control
	{
		self.mid_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn treble_control(&self) -> Control
	{
		self.treble_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn graphic_equalizer_control(&self) -> Control
	{
		self.graphic_equalizer_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn automatic_gain_control(&self) -> Control
	{
		self.automatic_gain_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn delay_control(&self) -> Control
	{
		self.delay_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn bass_boost_control(&self) -> Control
	{
		self.bass_boost_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn loudness_control(&self) -> Control
	{
		self.loudness_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn input_gain_control(&self) -> Control
	{
		self.input_gain_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn input_gain_pad_control(&self) -> Control
	{
		self.input_gain_pad_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn phase_inverter_control(&self) -> Control
	{
		self.phase_inverter_control
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
	
	#[inline(always)]
	fn parse(bmaControls: u32, channel_index: u8) -> Result<Self, Version2EntityDescriptorParseError>
	{
		use Version2EntityDescriptorParseError::*;
		
		Ok
		(
			Self
			{
				mute_control: Control::parse_u32(bmaControls, 0, FeatureUnitMuteControlInvalid { channel_index })?,
				
				volume_control: Control::parse_u32(bmaControls, 1, FeatureUnitVolumeControlInvalid { channel_index })?,
				
				bass_control: Control::parse_u32(bmaControls, 2, FeatureUnitBassControlInvalid { channel_index })?,
				
				mid_control: Control::parse_u32(bmaControls, 3, FeatureUnitMidControlInvalid { channel_index })?,
				
				treble_control: Control::parse_u32(bmaControls, 4, FeatureUnitTrebleControlInvalid { channel_index })?,
				
				graphic_equalizer_control: Control::parse_u32(bmaControls, 5, FeatureUnitGraphicEqualizerControlInvalid { channel_index })?,
				
				automatic_gain_control: Control::parse_u32(bmaControls, 6, FeatureUnitAutomaticGainControlInvalid { channel_index })?,
				
				delay_control: Control::parse_u32(bmaControls, 7, FeatureUnitDelayControlInvalid { channel_index })?,
				
				bass_boost_control: Control::parse_u32(bmaControls, 8, FeatureUnitBassBoostControlInvalid { channel_index })?,
				
				loudness_control: Control::parse_u32(bmaControls, 9, FeatureUnitLoudnessControlInvalid { channel_index })?,
				
				input_gain_control: Control::parse_u32(bmaControls, 10, FeatureUnitInputGainControlInvalid { channel_index })?,
				
				input_gain_pad_control: Control::parse_u32(bmaControls, 11, FeatureUnitInputGainPadControlInvalid { channel_index })?,
				
				phase_inverter_control: Control::parse_u32(bmaControls, 12, FeatureUnitPhaseInverterControlInvalid { channel_index })?,
				
				underflow_control: Control::parse_u32(bmaControls, 13, FeatureUnitUnderflowControlInvalid { channel_index })?,
				
				overflow_control: Control::parse_u32(bmaControls, 14, FeatureUnitOverflowControlInvalid { channel_index })?,
			}
		)
	}
}
