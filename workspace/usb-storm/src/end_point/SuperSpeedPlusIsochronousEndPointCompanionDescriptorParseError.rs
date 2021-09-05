// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum SuperSpeedPlusIsochronousEndPointCompanionDescriptorParseError
{
	#[allow(missing_docs)]
	ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorMissing,
	
	#[allow(missing_docs)]
	ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorTypeWrong
	{
		bDescriptorType: u8,
	},
	
	#[allow(missing_docs)]
	ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorBLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorBLengthExceedsRemainingBytes,
}

impl Display for SuperSpeedPlusIsochronousEndPointCompanionDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for SuperSpeedPlusIsochronousEndPointCompanionDescriptorParseError
{
}
