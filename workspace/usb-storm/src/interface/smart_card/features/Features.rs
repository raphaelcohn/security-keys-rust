// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Features of a smart card.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Features
{
	automatic: BitFlags<AutomaticFeature>,
	
	automatic_for_protocol_t_1: Option<BitFlags<T1ProtocolAutomaticFeature>>,
	
	automatic_parameters: BitFlags<AutomaticParametersFeature>,
	
	level_of_exchange: LevelOfExchange,

	usb_wake_up_signaling_on_card_insertion_and_removal: bool,
}

impl Features
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn automatic(&self) -> BitFlags<AutomaticFeature>
	{
		self.automatic
	}
	
	/// `None` if protocol T=1 is not supported.
	#[inline(always)]
	pub const fn automatic_for_protocol_t_1(&self) -> Option<BitFlags<T1ProtocolAutomaticFeature>>
	{
		self.automatic_for_protocol_t_1
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn automatic_parameters(&self) -> BitFlags<AutomaticParametersFeature>
	{
		self.automatic_parameters
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn level_of_exchange(&self) -> LevelOfExchange
	{
		self.level_of_exchange
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn usb_wake_up_signaling_on_card_insertion_and_removal(&self) -> bool
	{
		self.usb_wake_up_signaling_on_card_insertion_and_removal
	}
	
	#[inline(always)]
	pub(super) fn parse(dwFeatures: u32, iso_7816_protocols: BitFlags<Iso7816Protocol>) -> Result<Self, FeaturesParseError>
	{
		let level_of_exchange = LevelOfExchange::parse(dwFeatures)?;
		let automatic = AutomaticFeature::parse(dwFeatures);
		let automatic_parameters = AutomaticParametersFeature::parse(dwFeatures);
		
		// cf DWG Smart Card CCID Revision 1.1, page 19.
		if level_of_exchange.is_apdu_level()
		{
			use FeaturesParseError::*;
			
			if !automatic.contains(AutomaticFeature::AutomaticParameterConfigurationBasedOnAnswerToResetData)
			{
				return Err(MissingFeatureAutomaticParameterConfigurationBasedOnAnswerToResetDataForApduLevelOfExchange)
			}
			
			if automatic_parameters.is_empty()
			{
				return Err(MissingFeatureAutomaticParametersForApduLevelOfExchange)
			}
		}
		
		Ok
		(
			Self
			{
				automatic,
				
				automatic_for_protocol_t_1: if iso_7816_protocols.contains(Iso7816Protocol::T1)
				{
					Some(T1ProtocolAutomaticFeature::parse(dwFeatures))
				}
				else
				{
					None
				},
				
				automatic_parameters,
				
				level_of_exchange,
				
				usb_wake_up_signaling_on_card_insertion_and_removal: dwFeatures & 0x00100000 != 0,
			}
		)
	}
}
