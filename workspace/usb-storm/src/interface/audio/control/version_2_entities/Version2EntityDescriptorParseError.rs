// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version2EntityDescriptorParseError
{
	#[allow(missing_docs)]
	InputTerminalTypeParse(TerminalTypeParseError),
	
	#[allow(missing_docs)]
	OutputTerminalTypeParse(TerminalTypeParseError),
	
	#[allow(missing_docs)]
	LogicalAudioChannelClusterParse(LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>),
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	SelectorClockCouldNotAllocateSources(TryReserveError),
	
	#[allow(missing_docs)]
	SelectorClockPIsTooLarge,
	
	#[allow(missing_docs)]
	MixerUnitBLengthTooShort,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForSources(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForMixerControls(TryReserveError),
	
	#[allow(missing_docs)]
	MixerUnitClusterControlInvalid,
	
	#[allow(missing_docs)]
	MixerUnitUnderflowControlInvalid,
	
	#[allow(missing_docs)]
	MixerUnitOverflowControlInvalid,
	
	#[allow(missing_docs)]
	MultiplierClockNumeratorControlInvalid,
	
	#[allow(missing_docs)]
	MultiplierClockDenominatorControlInvalid,
	
	#[allow(missing_docs)]
	SelectorClockSelectorControlInvalid,
	
	#[allow(missing_docs)]
	SourceClockFrequencyControlInvalid,
	
	#[allow(missing_docs)]
	SourceClockValidityControlInvalid,
	
	#[allow(missing_docs)]
	InputTerminalCopyProtectControlInvalid,
	
	#[allow(missing_docs)]
	InputTerminalConnectorControlInvalid,
	
	#[allow(missing_docs)]
	InputTerminalOverloadControlInvalid,
	
	#[allow(missing_docs)]
	InputTerminalClusterControlInvalid,
	
	#[allow(missing_docs)]
	InputTerminalUnderflowControlInvalid,
	
	#[allow(missing_docs)]
	InputTerminalOverflowControlInvalid,
	
	#[allow(missing_docs)]
	OutputTerminalCopyProtectControlInvalid,
	
	#[allow(missing_docs)]
	OutputTerminalConnectorControlInvalid,
	
	#[allow(missing_docs)]
	OutputTerminalOverloadControlInvalid,
	
	#[allow(missing_docs)]
	OutputTerminalUnderflowControlInvalid,
	
	#[allow(missing_docs)]
	OutputTerminalOverflowControlInvalid,
	
	#[allow(missing_docs)]
	SelectorUnitLengthWrong,
	
	#[allow(missing_docs)]
	SelectorUnitSelectorControlInvalid,
	
	#[allow(missing_docs)]
	FeatureUnitControlsLengthNotAMultipleOfFour,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForFeatureControls(TryReserveError),
	
	#[allow(missing_docs)]
	FeatureUnitMuteControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitVolumeControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitBassControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitMidControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitTrebleControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitGraphicEqualizerControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitAutomaticGainControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitDelayControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitBassBoostControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitLoudnessControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitInputGainControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitInputGainPadControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitPhaseInverterControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitUnderflowControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	FeatureUnitOverflowControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	EffectUnitControlsLengthNotAMultipleOfFour,
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitEnableControlInvalid,
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitCenterFrequencyControlInvalid,
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitQFactorControlInvalid,
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitGainControlInvalid,
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitUnderflowControlInvalid,
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitOverflowControlInvalid,
	
	#[allow(missing_docs)]
	ReverberationEffectUnitEnableControlInvalid,
	
	#[allow(missing_docs)]
	ReverberationEffectUnitTypeControlInvalid,
	
	#[allow(missing_docs)]
	ReverberationEffectUnitLevelControlInvalid,
	
	#[allow(missing_docs)]
	ReverberationEffectUnitTimeControlInvalid,
	
	#[allow(missing_docs)]
	ReverberationEffectUnitDelayFeedbackControlInvalid,
	
	#[allow(missing_docs)]
	ReverberationEffectUnitPreDelayControlInvalid,
	
	#[allow(missing_docs)]
	ReverberationEffectUnitDensityControlInvalid,
	
	#[allow(missing_docs)]
	ReverberationEffectUnitHighFrequencyRollOffControlInvalid,
	
	#[allow(missing_docs)]
	ReverberationEffectUnitUnderflowControlInvalid,
	
	#[allow(missing_docs)]
	ReverberationEffectUnitOverflowControlInvalid,
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitEnableControlInvalid,
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitBalanceControlInvalid,
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitRateControlInvalid,
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitDepthControlInvalid,
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitTimeControlInvalid,
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitFeedbackLevelControlInvalid,
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitUnderflowControlInvalid,
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitOverflowControlInvalid,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitEnableControlInvalid,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitCompressionRatioControlInvalid,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitMaximumAmplitudeControlInvalid,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitThresholControlInvalid,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitAttackTimeControlInvalid,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitReleaseTimeControlInvalid,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitUnderflowControlInvalid,
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitOverflowControlInvalid,
}

impl Display for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2EntityDescriptorParseError::*;
		
		match self
		{
			InputTerminalTypeParse(cause) => Some(cause),
			
			OutputTerminalTypeParse(cause) => Some(cause),
			
			LogicalAudioChannelClusterParse(cause) => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
			
			SelectorClockCouldNotAllocateSources(cause) => Some(cause),
			
			CouldNotAllocateMemoryForSources(cause) => Some(cause),
			
			CouldNotAllocateMemoryForMixerControls(cause) => Some(cause),
			
			CouldNotAllocateMemoryForFeatureControls(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>) -> Self
	{
		Version2EntityDescriptorParseError::LogicalAudioChannelClusterParse(cause)
	}
}
