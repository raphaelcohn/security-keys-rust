// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version2EntityDescriptorParseError
{
	#[allow(missing_docs)]
	InputTerminalEntityParse(Version2InputTerminalEntityParseError),
	
	#[allow(missing_docs)]
	OutputTerminalEntityParse(Version2OutputTerminalEntityParseError),
	
	#[allow(missing_docs)]
	MixerUnitEntityParse(Version2MixerUnitEntityParseError),
	
	#[allow(missing_docs)]
	SelectorUnitEntityParse(Version2SelectorUnitEntityParseError),
	
	#[allow(missing_docs)]
	FeatureUnitEntityParse(Version2FeatureUnitEntityParseError),
	
	#[allow(missing_docs)]
	ProcessingUnitEntityParse(Version2ProcessingUnitEntityParseError),
	
	#[allow(missing_docs)]
	ExtensionUnitEntityParse(Version2ExtensionUnitEntityParseError),
	
	#[allow(missing_docs)]
	SamplingRateConverterUnitEntityParse(Version2ExtensionUnitEntityParseError),
	
	#[allow(missing_docs)]
	SelectorClockEntityParse(Version2SelectorClockEntityParseError),
	
	#[allow(missing_docs)]
	MultiplierClockEntityParse(Version2MultiplierClockEntityParseError),
	
	#[allow(missing_docs)]
	SourceClockEntityParse(Version2SourceClockEntityParseError),
	
	
	
	
	
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
	EffectUnitControlsLengthNotAMultipleOfFour
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitEnableControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitCenterFrequencyControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitQFactorControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitGainControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitUnderflowControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ParametericEqualizerSectionEffectUnitOverflowControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ReverberationEffectUnitEnableControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ReverberationEffectUnitTypeControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ReverberationEffectUnitLevelControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ReverberationEffectUnitTimeControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ReverberationEffectUnitDelayFeedbackControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ReverberationEffectUnitPreDelayControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ReverberationEffectUnitDensityControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ReverberationEffectUnitHighFrequencyRollOffControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ReverberationEffectUnitUnderflowControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ReverberationEffectUnitOverflowControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitEnableControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitBalanceControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitRateControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitDepthControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitTimeControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitFeedbackLevelControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitUnderflowControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	ModulationDelayEffectUnitOverflowControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitEnableControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitCompressionRatioControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitMaximumAmplitudeControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitThresholControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitAttackTimeControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitReleaseTimeControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitUnderflowControlInvalid
	{
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectUnitOverflowControlInvalid
	{
		channel_index: u8,
	},
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
			InputTerminalEntityParse(cause) => Some(cause),
			
			OutputTerminalEntityParse(cause) => Some(cause),
			
			SelectorUnitEntityParse(cause) => Some(cause),
			
			MixerUnitEntityParse(cause) => Some(cause),
			
			FeatureUnitEntityParse(cause) => Some(cause),
			
			ProcessingUnitEntityParse(cause) => Some(cause),
			
			ExtensionUnitEntityParse(cause) => Some(cause),
			
			SamplingRateConverterUnitEntityParse(cause) => Some(cause),
			
			SelectorClockEntityParse(cause) => Some(cause),
			
			MultiplierClockEntityParse(cause) => Some(cause),
			
			SourceClockEntityParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<Version2InputTerminalEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version2InputTerminalEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::InputTerminalEntityParse(cause)
	}
}

impl From<Version2OutputTerminalEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version2OutputTerminalEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::OutputTerminalEntityParse(cause)
	}
}

impl From<Version2MixerUnitEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version2MixerUnitEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::MixerUnitEntityParse(cause)
	}
}

impl From<Version2SelectorUnitEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version2SelectorUnitEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::SelectorUnitEntityParse(cause)
	}
}

impl From<Version2FeatureUnitEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version2FeatureUnitEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::FeatureUnitEntityParse(cause)
	}
}

impl From<Version2ProcessingUnitEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version2ProcessingUnitEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::ProcessingUnitEntityParse(cause)
	}
}

impl From<Version2ExtensionUnitEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: Version2ExtensionUnitEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::ExtensionUnitEntityParse(cause)
	}
}

impl From<SamplingRateConverterUnitEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: SamplingRateConverterUnitEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::SamplingRateConverterUnitEntityParse(cause)
	}
}

impl From<SelectorClockEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: SelectorClockEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::SelectorClockEntityParse(cause)
	}
}

impl From<MultiplierClockEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: MultiplierClockEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::MultiplierClockEntityParse(cause)
	}
}

impl From<SourceClockEntityParseError> for Version2EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: SourceClockEntityParseError) -> Self
	{
		Version2EntityDescriptorParseError::SourceClockEntityParse(cause)
	}
}
