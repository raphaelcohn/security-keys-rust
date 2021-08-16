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
	fn parse_undefined(controls: u32) -> Result<Self, Version2EntityDescriptorParseError>
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
	fn parse_parametric_equalizer_section(controls: u32) -> Result<Self, Version2EntityDescriptorParseError>
	{
		use Version2EntityDescriptorParseError::*;
		
		Ok
		(
			Version2AudioChannelEffectControls::ParametericEqualizerSection
			{
				enable_control: Control::parse_u32(controls, 0, ParametericEqualizerSectionEffectUnitEnableControlInvalid)?,
				
				center_frequency_control: Control::parse_u32(controls, 1, ParametericEqualizerSectionEffectUnitCenterFrequencyControlInvalid)?,
				
				q_factor_control: Control::parse_u32(controls, 2, ParametericEqualizerSectionEffectUnitQFactorControlInvalid)?,
				
				gain_control: Control::parse_u32(controls, 3, ParametericEqualizerSectionEffectUnitGainControlInvalid)?,
				
				underflow_control: Control::parse_u32(controls, 4, ParametericEqualizerSectionEffectUnitUnderflowControlInvalid)?,
				
				overflow_control: Control::parse_u32(controls, 5, ParametericEqualizerSectionEffectUnitOverflowControlInvalid)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_reverberation(controls: u32) -> Result<Self, Version2EntityDescriptorParseError>
	{
		use Version2EntityDescriptorParseError::*;
		
		Ok
		(
			Version2AudioChannelEffectControls::Reverberation
			{
				enable_control: Control::parse_u32(controls, 0, ReverberationEffectUnitEnableControlInvalid)?,
				
				type_control: Control::parse_u32(controls, 1, ReverberationEffectUnitTypeControlInvalid)?,
				
				level_control: Control::parse_u32(controls, 2, ReverberationEffectUnitLevelControlInvalid)?,
				
				time_control: Control::parse_u32(controls, 3, ReverberationEffectUnitTimeControlInvalid)?,
				
				delay_feedback_control: Control::parse_u32(controls, 4, ReverberationEffectUnitDelayFeedbackControlInvalid)?,
				
				pre_delay_control: Control::parse_u32(controls, 5, ReverberationEffectUnitPreDelayControlInvalid)?,
				
				density_control: Control::parse_u32(controls, 6, ReverberationEffectUnitDensityControlInvalid)?,
				
				high_frequency_roll_off_control: Control::parse_u32(controls, 7, ReverberationEffectUnitHighFrequencyRollOffControlInvalid)?,
				
				underflow_control: Control::parse_u32(controls, 8, ReverberationEffectUnitUnderflowControlInvalid)?,
				
				overflow_control: Control::parse_u32(controls, 9, ReverberationEffectUnitOverflowControlInvalid)?,
				
			}
		)
	}
	
	#[inline(always)]
	fn parse_modulation_delay(controls: u32) -> Result<Self, Version2EntityDescriptorParseError>
	{
		use Version2EntityDescriptorParseError::*;
		
		Ok
		(
			Version2AudioChannelEffectControls::ModulationDelay
			{
				enable_control: Control::parse_u32(controls, 0, ModulationDelayEffectUnitEnableControlInvalid)?,
				
				balance_control: Control::parse_u32(controls, 1, ModulationDelayEffectUnitBalanceControlInvalid)?,
				
				rate_control: Control::parse_u32(controls, 2, ModulationDelayEffectUnitRateControlInvalid)?,
				
				depth_control: Control::parse_u32(controls, 3, ModulationDelayEffectUnitDepthControlInvalid)?,
				
				time_control: Control::parse_u32(controls, 4, ModulationDelayEffectUnitTimeControlInvalid)?,
				
				feedback_level_control: Control::parse_u32(controls, 5, ModulationDelayEffectUnitFeedbackLevelControlInvalid)?,
				
				underflow_control: Control::parse_u32(controls, 6, ModulationDelayEffectUnitUnderflowControlInvalid)?,
				
				overflow_control: Control::parse_u32(controls, 7, ModulationDelayEffectUnitOverflowControlInvalid)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_dynamic_range_compressor(controls: u32) -> Result<Self, Version2EntityDescriptorParseError>
	{
		use Version2EntityDescriptorParseError::*;
		
		Ok
		(
			Version2AudioChannelEffectControls::DynamicRangeCompressor
			{
				enable_control: Control::parse_u32(controls, 0, DynamicRangeCompressorEffectUnitEnableControlInvalid)?,
				
				compression_ratio_control: Control::parse_u32(controls, 1, DynamicRangeCompressorEffectUnitCompressionRatioControlInvalid)?,
				
				maximum_amplitude_control: Control::parse_u32(controls, 2, DynamicRangeCompressorEffectUnitMaximumAmplitudeControlInvalid)?,
				
				threshold_control: Control::parse_u32(controls, 3, DynamicRangeCompressorEffectUnitThresholControlInvalid)?,
				
				attack_time_control: Control::parse_u32(controls, 4, DynamicRangeCompressorEffectUnitAttackTimeControlInvalid)?,
				
				release_time_control: Control::parse_u32(controls, 5, DynamicRangeCompressorEffectUnitReleaseTimeControlInvalid)?,
				
				underflow_control: Control::parse_u32(controls, 6, DynamicRangeCompressorEffectUnitUnderflowControlInvalid)?,
				
				overflow_control: Control::parse_u32(controls, 7, DynamicRangeCompressorEffectUnitOverflowControlInvalid)?,
				
			}
		)
	}
	
	#[inline(always)]
	fn parse_unrecognized(controls: u32, effect_type_code: NonZeroU16) -> Result<Self, Version2EntityDescriptorParseError>
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
