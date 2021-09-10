// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ProcessingUnitEntityParseError
{
	#[allow(missing_docs)]
	BLengthTooShort
	{
		bLength: u8,
	},

	#[allow(missing_docs)]
	InvalidCombinationOfDigitalMultiplierValues
	{
		wMaxMultiplier: Option<NonZeroU16>,
		
		digital_multiplier_supported: bool,
		
		digital_multiplier_limit: bool,
	},
	
	#[allow(missing_docs)]
	InvalidCombinationOfAnalogVideoValues
	{
		bmVideoStandards: Option<NonZeroU8>,
		
		analog_video_standard: bool,
		
		analog_video_lock_status: bool,
	},
	
	#[allow(missing_docs)]
	Version_1_5_HasInvalidControlSize
	{
		bControlSize: u8,
	},
	
	#[allow(missing_docs)]
	BLengthTooShortForControlSize
	{
		bLength: u8,
		
		bControlSize: u8,
		
		specification_version: Version,
	},
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
}

impl Display for ProcessingUnitEntityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ProcessingUnitEntityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use ProcessingUnitEntityParseError::*;
		
		match self
		{
			InvalidDescriptionString(cause) => Some(cause),
			
			_ => None,
		}
	}
}
