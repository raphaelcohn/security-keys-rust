// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Human Interface Device (HID) descriptor parse error.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum FeaturesParseError
{
	/// Can not have more than one of TpduLevelExchangeWithCcid, ShortApduLevelExchangeWithCcid or ShortAndExtendedApduLevelExchangeWithCcid.
	InvalidLevelOfExchangeFeature,
	
	/// When an APDU level of exchange is selected, one of the values 00000040h or 00000080h must be present.
	MissingFeatureAutomaticParametersForApduLevelOfExchange,
	
	/// When an APDU level of exchange is selected, the value 00000002h must be present.
	MissingFeatureAutomaticParameterConfigurationBasedOnAnswerToResetDataForApduLevelOfExchange,
}

impl Display for FeaturesParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for FeaturesParseError
{
}
