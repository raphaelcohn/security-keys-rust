// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum SuperSpeedEndPointCompanionDescriptorParseError
{
	#[allow(missing_docs)]
	SuperSpeedCompanionBLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	SuperSpeedCompanionBLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	ControlEndPointsDoNotSupportPacketBurst,
	
	#[allow(missing_docs)]
	InvalidMaximumBurst
	{
		bMaxBurst: u8,
	},
	
	#[allow(missing_docs)]
	InvalidMaximumStreams
	{
		maximum_streams: u8
	},
	
	#[allow(missing_docs)]
	BytesIntervalMustBeOneIfAnIsochronousEndPointHasASuperSpeedPlusIsochronousEndPointCompanionIndicated,
	
	#[allow(missing_docs)]
	MultIsNotZeroWhenMaximumBurstIsZero
	{
		mult: u2,
	},
	
	#[allow(missing_docs)]
	MultCanNotBeThree,
	
	#[allow(missing_docs)]
	SuperSpeedPlusIsochronousEndPointCompanionDescriptorParse(SuperSpeedPlusIsochronousEndPointCompanionDescriptorParseError),
}

impl Display for SuperSpeedEndPointCompanionDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for SuperSpeedEndPointCompanionDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use SuperSpeedEndPointCompanionDescriptorParseError::*;
		
		match self
		{
			SuperSpeedPlusIsochronousEndPointCompanionDescriptorParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<SuperSpeedPlusIsochronousEndPointCompanionDescriptorParseError> for SuperSpeedEndPointCompanionDescriptorParseError
{
	#[inline(always)]
	fn from(cause: SuperSpeedPlusIsochronousEndPointCompanionDescriptorParseError) -> Self
	{
		SuperSpeedEndPointCompanionDescriptorParseError::SuperSpeedPlusIsochronousEndPointCompanionDescriptorParse(cause)
	}
}
