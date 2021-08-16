// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio channel feature controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2AudioChannelEffectControls
{
	#[allow(missing_docs)]
	Undefined
	{
		controls: u32
	},
	
	#[allow(missing_docs)]
	ParametericEqualizerSection
	{
		enable_control: Control,
		
		center_frequency_control: Control,
		
		q_factor_control: Control,
		
		gain_control: Control,
		
		underflow_control: Control,
		
		overflow_control: Control,
	},
	
	#[allow(missing_docs)]
	Reverberation
	{
		enable_control: Control,
		
		type_control: Control,
		
		level_control: Control,
		
		time_control: Control,
		
		delay_feedback_control: Control,
		
		pre_delay_control: Control,
		
		density_control: Control,
		
		high_frequency_roll_off_control: Control,
		
		underflow_control: Control,
		
		overflow_control: Control,
	},
	
	#[allow(missing_docs)]
	ModulationDelay
	{
		enable_control: Control,
		
		balance_control: Control,
		
		rate_control: Control,
		
		depth_control: Control,
		
		time_control: Control,
		
		feedback_level_control: Control,
		
		underflow_control: Control,
		
		overflow_control: Control,
	},
	
	#[allow(missing_docs)]
	DynamicRangeCompressor
	{
		enable_control: Control,
		
		compression_ratio_control: Control,
		
		maximum_amplitude_control: Control,
		
		threshold_control: Control,
		
		attack_time_control: Control,
		
		release_time_control: Control,
		
		underflow_control: Control,
		
		overflow_control: Control,
	},
	
	#[allow(missing_docs)]
	Unrecognized
	{
		effect_type_code: NonZeroU16,
	
		controls: u32,
	}
}

impl Version2AudioChannelEffectControls
{
	#[inline(always)]
	fn parse_undefined(controls: u32) -> Result<Self, Infallible>
	{
		Ok
		(
			Version2AudioChannelEffectControls::Undefined
			{
				controls
			}
		)
	}
	
	#[inline(always)]
	fn parse_parametric_equalizer_section(controls: u32) -> Result<Self, ParametricEqualizerSectionControlsParseError>
	{
		use ParametricEqualizerSectionControlsParseError::*;
		
		Ok
		(
			Version2AudioChannelEffectControls::ParametericEqualizerSection
			{
				enable_control: Control::parse_u32(controls, 0, Enable)?,
				
				center_frequency_control: Control::parse_u32(controls, 1, CenterFrequency)?,
				
				q_factor_control: Control::parse_u32(controls, 2, QFactor)?,
				
				gain_control: Control::parse_u32(controls, 3, Gain)?,
				
				underflow_control: Control::parse_u32(controls, 4, Underflow)?,
				
				overflow_control: Control::parse_u32(controls, 5, Overflow)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_reverberation(controls: u32) -> Result<Self, ReverberationControlsParseError>
	{
		use ReverberationControlsParseError::*;
		
		Ok
		(
			Version2AudioChannelEffectControls::Reverberation
			{
				enable_control: Control::parse_u32(controls, 0, Enable)?,
				
				type_control: Control::parse_u32(controls, 1, Type)?,
				
				level_control: Control::parse_u32(controls, 2, Level)?,
				
				time_control: Control::parse_u32(controls, 3, Time)?,
				
				delay_feedback_control: Control::parse_u32(controls, 4, DelayFeedback)?,
				
				pre_delay_control: Control::parse_u32(controls, 5, PreDelay)?,
				
				density_control: Control::parse_u32(controls, 6, Density)?,
				
				high_frequency_roll_off_control: Control::parse_u32(controls, 7, HighFrequencyRollOff)?,
				
				underflow_control: Control::parse_u32(controls, 8, Underflow)?,
				
				overflow_control: Control::parse_u32(controls, 9, Overflow)?,
				
			}
		)
	}
	
	#[inline(always)]
	fn parse_modulation_delay(controls: u32) -> Result<Self, ModulationDelayControlsParseError>
	{
		use ModulationDelayControlsParseError::*;
		
		Ok
		(
			Version2AudioChannelEffectControls::ModulationDelay
			{
				enable_control: Control::parse_u32(controls, 0, Enable)?,
				
				balance_control: Control::parse_u32(controls, 1, Balance)?,
				
				rate_control: Control::parse_u32(controls, 2, Rate)?,
				
				depth_control: Control::parse_u32(controls, 3, Depth)?,
				
				time_control: Control::parse_u32(controls, 4, Time)?,
				
				feedback_level_control: Control::parse_u32(controls, 5, FeedbackLevel)?,
				
				underflow_control: Control::parse_u32(controls, 6, Underflow)?,
				
				overflow_control: Control::parse_u32(controls, 7, Overflow)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_dynamic_range_compressor(controls: u32) -> Result<Self, DynamicRangeCompressorControlsParseError>
	{
		use DynamicRangeCompressorControlsParseError::*;
		
		Ok
		(
			Version2AudioChannelEffectControls::DynamicRangeCompressor
			{
				enable_control: Control::parse_u32(controls, 0, Enable)?,
				
				compression_ratio_control: Control::parse_u32(controls, 1, CompressionRatio)?,
				
				maximum_amplitude_control: Control::parse_u32(controls, 2, MaximumAmplitude)?,
				
				threshold_control: Control::parse_u32(controls, 3, Threshol)?,
				
				attack_time_control: Control::parse_u32(controls, 4, AttackTime)?,
				
				release_time_control: Control::parse_u32(controls, 5, ReleaseTime)?,
				
				underflow_control: Control::parse_u32(controls, 6, Underflow)?,
				
				overflow_control: Control::parse_u32(controls, 7, Overflow)?,
				
			}
		)
	}
	
	#[inline(always)]
	fn parse_unrecognized(controls: u32, effect_type_code: NonZeroU16) -> Result<Self, Infallible>
	{
		Ok
		(
			Version2AudioChannelEffectControls::Unrecognized
			{
				effect_type_code,
				
				controls,
			}
		)
	}
}
