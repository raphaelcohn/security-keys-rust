// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// End Point descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum EndPointExtraDescriptorParseError
{
	SuperSpeedCompanionBLengthIsLessThanMinimum,
	
	SuperSpeedCompanionBLengthExceedsRemainingBytes,
	
	ControlEndPointsDoNotSupportPacketBurst,
	
	InvalidMaximumBurst
	{
		bMaxBurst: u8,
	},
	
	InvalidMaximumStreams
	{
		maximum_streams: u8
	},
	
	BytesIntervalMustBeOneIfAnIsochronousEndPointHasASuperSpeedPlusIsochronousEndPointCompanionIndicated,
	
	MultIsNotZeroWhenMaximumBurstIsZero
	{
		mult: u2,
	},
	
	MultCanNotBeThree,
	
	ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorMissing,
	
	ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorTypeWrong
	{
		bDescriptorType: u8,
	},
	
	ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorBLengthIsLessThanMinimum,
	
	ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorBLengthExceedsRemainingBytes,
	
	UsbAttachedScsiPipeBLengthIsLessThanMinimum,
	
	UsbAttachedScsiPipeBLengthExceedsRemainingBytes,
}

impl Display for EndPointExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for EndPointExtraDescriptorParseError
{
}
