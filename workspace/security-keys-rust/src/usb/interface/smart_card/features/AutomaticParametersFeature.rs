// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u32)]
pub(crate) enum AutomaticParametersFeature
{
	Off = 0x0000_0000,
	
	/// Use of warm or cold resets or PPS according to a manufacturer proprietary algorithm to select the communication parameters with the ICC.
	AutomaticParametersNegotiationMadeByTheCcid = 0x0000_0040,
	
	AutomaticPpsMadeByTheCcidAccordingToTheActiveParameters = 0x0000_0080,
}

impl AutomaticParametersFeature
{
	#[inline(always)]
	fn parse(dwFeatures: u32) -> Result<Self, SmartCardInterfaceAdditionalDescriptorParseError>
	{
		const AutomaticParametersNegotiationMadeByTheCcid: u32 = AutomaticParametersFeature::AutomaticParametersNegotiationMadeByTheCcid as u32;
		const AutomaticPpsMadeByTheCcidAccordingToTheActiveParameters: u32 = AutomaticParametersFeature::AutomaticPpsMadeByTheCcidAccordingToTheActiveParameters as u32;
		const Mask: u32 = AutomaticParametersNegotiationMadeByTheCcid | AutomaticPpsMadeByTheCcidAccordingToTheActiveParameters;
		match dwFeatures & Mask
		{
			0 => Ok(AutomaticParametersFeature::Off),
			
			AutomaticParametersNegotiationMadeByTheCcid => Ok(AutomaticParametersFeature::AutomaticParametersNegotiationMadeByTheCcid),
			
			AutomaticPpsMadeByTheCcidAccordingToTheActiveParameters => Ok(AutomaticParametersFeature::AutomaticPpsMadeByTheCcidAccordingToTheActiveParameters),
			
			_ => Err(SmartCardInterfaceAdditionalDescriptorParseError::InvalidAutomaticParametersFeature)
		}
	}
}
