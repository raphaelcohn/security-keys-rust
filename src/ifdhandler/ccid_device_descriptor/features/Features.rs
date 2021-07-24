// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub(crate) struct Features
{
	automatic: BitFlags<AutomaticFeature>,
	
	automatic_parameters: AutomaticParametersFeature,
	
	level_of_exchange: LevelOfExchangeFeature,

	usb_wake_up_signaling_on_card_insertion_and_removal: bool,
}

impl Features
{
	#[inline(always)]
	pub(super) fn parse(dwFeatures: u32) -> Result<Self, &'static str>
	{
		let automatic = AutomaticFeature::parse(dwFeatures)?;
		let automatic_parameters = AutomaticParametersFeature::parse(dwFeatures)?;
		let level_of_exchange = LevelOfExchangeFeature::parse(dwFeatures)?;
		let usb_wake_up_signaling_on_card_insertion_and_removal = dwFeatures & 0x00100000 != 0;
		
		// cf DWG Smart Card CCID Revision 1.1, page 19.
		if level_of_exchange.is_apdu_level()
		{
			if automatic_parameters == AutomaticParametersFeature::Off
			{
				return Err("When an APDU level of exchange is selected,  one of the values 00000040h or 00000080h must be present")
			}
			
			if !automatic.contains(AutomaticFeature::AutomaticParameterConfigurationBasedOnAnswerToResetData)
			{
				return Err("When an APDU level of exchange is selected, the value 00000002h must be present")
			}
		}
		
		Ok
		(
			Self
			{
				automatic,
				
				automatic_parameters,
				
				level_of_exchange,
				
				usb_wake_up_signaling_on_card_insertion_and_removal,
			}
		)
	}
}
