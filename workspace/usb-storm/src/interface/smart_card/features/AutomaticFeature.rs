// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Automatic features.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u32)]
pub enum AutomaticFeature
{
	#[allow(missing_docs)]
	AutomaticParameterConfigurationBasedOnAnswerToResetData = 0x0000_0002,
	
	#[allow(missing_docs)]
	AutomaticActivationOfIccOnInserting = 0x0000_0004,
	
	#[allow(missing_docs)]
	AutomaticIccVoltageSelection = 0x0000_0008,
	
	#[allow(missing_docs)]
	AutomaticIccClockFrequencyChangeAccordingToActiveParametersProvidedByTheHostOrSelfDetermined = 0x0000_0010,
	
	#[allow(missing_docs)]
	AutomaticBaudRateChangeAccordingToActiveParametersProvidedByTheHostOrSelfDetermined = 0x0000_0020,
	
	#[allow(missing_docs)]
	CcidCanSetIccInClockStopMode = 0x0000_0100,
	
	/// T=1 protocol in use.
	NadValueOtherThan00Accepted = 0x0000_0200,
	
	/// T=1 protocol in use.
	AutomaticIfsdExchangeAsFirstExchange = 0x0000_0400,
}

impl AutomaticFeature
{
	#[inline(always)]
	fn parse(dwFeatures: u32) -> Result<BitFlags<Self>, SmartCardInterfaceAdditionalDescriptorParseError>
	{
		if dwFeatures & 0b1111_1000_0000_0001 != 0
		{
			Err(SmartCardInterfaceAdditionalDescriptorParseError::AutomaticFeatureBit0OrBits12To15Set)
		}
		else
		{
			Ok(BitFlags::from_bits_truncate(dwFeatures))
		}
	}
}
