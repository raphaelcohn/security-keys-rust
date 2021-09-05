// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A parse error.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
pub enum SuperSpeedDeviceCapabilityParseError
{
	#[allow(missing_docs)]
	TooShort,
	
	#[allow(missing_docs)]
	HasReservedAttributesBitsSet,
	
	#[allow(missing_docs)]
	HasReservedSpeedsSupportedBitsSet,
	
	#[allow(missing_docs)]
	HasInvalidFunctionalitySupportSpeed
	{
		bFunctionalitySupport: u8,
	},
	
	#[allow(missing_docs)]
	HasFunctionalitySupportSpeedMissingFromSupportedSpeeds
	{
		lowest_speed_that_supports_all_functionality: SuperSpeedDeviceCapabilitySupportedSpeed,
	},
	
	#[allow(missing_docs)]
	HasReservedU1DeviceExitLatency
	{
		bU1DevExitLat: u8,
	},
	
	#[allow(missing_docs)]
	HasReservedU2DeviceExitLatency
	{
		bU2DevExitLat: u16,
	},
}

impl Display for SuperSpeedDeviceCapabilityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for SuperSpeedDeviceCapabilityParseError
{
}
