// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2EffectUnitEntityParseError
{
	#[allow(missing_docs)]
	UndefinedEffectTypeParse(Version2EffectTypeParseError<InfallibleError>),
	
	#[allow(missing_docs)]
	ParametricEqualizerSectionEffectTypeParse(Version2EffectTypeParseError<ParametricEqualizerSectionControlsParseError>),
	
	#[allow(missing_docs)]
	ReverberationEffectTypeParse(Version2EffectTypeParseError<ReverberationControlsParseError>),
	
	#[allow(missing_docs)]
	ModulationDelayEffectTypeParse(Version2EffectTypeParseError<ModulationDelayControlsParseError>),
	
	#[allow(missing_docs)]
	DynamicRangeCompressorEffectTypeParse(Version2EffectTypeParseError<DynamicRangeCompressorControlsParseError>),
	
	#[allow(missing_docs)]
	UnrecognizedEffectTypeParse(Version2EffectTypeParseError<InfallibleError>),
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
}

impl Display for Version2EffectUnitEntityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2EffectUnitEntityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2EffectUnitEntityParseError::*;
		
		match self
		{
			UndefinedEffectTypeParse(cause) => Some(cause),
			
			ParametricEqualizerSectionEffectTypeParse(cause) => Some(cause),
			
			ReverberationEffectTypeParse(cause) => Some(cause),
			
			ModulationDelayEffectTypeParse(cause) => Some(cause),
			
			DynamicRangeCompressorEffectTypeParse(cause) => Some(cause),
			
			UnrecognizedEffectTypeParse(cause) => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
		}
	}
}
