// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A parse error.
#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum SuperSpeedPlusDeviceCapabilityParseError
{
	#[allow(missing_docs)]
	TooShort,
	
	#[allow(missing_docs)]
	HasReservedByteSet,
	
	#[allow(missing_docs)]
	HasReservedAttributesBitsSet,
	
	#[allow(missing_docs)]
	TheNumberOfSublinksIsNotPaired,
	
	#[allow(missing_docs)]
	HasReservedFunctionalitySupportBitsSet,
	
	#[allow(missing_docs)]
	HasReservedWordSet,
	
	#[allow(missing_docs)]
	NotEnoughBytesForSublinkSpeedAttributes,
	
	#[allow(missing_docs)]
	SublinkSpeedAttributeHasReservedBits
	{
		sublink_speed_attribute_index: u4,
	},
	
	#[allow(missing_docs)]
	SublinkSpeedAttributeHasReservedLinkProtocol
	{
		sublink_speed_attribute_index: u4,

		/// Only possible values are 2 and 3.
		sublink_protocol: u2,
	},
	
	#[allow(missing_docs)]
	DuplicateSublinkTypeForSublinkSpeedAttribute
	{
		sublink_speed_attribute_index: u4,
	},
	
	#[allow(missing_docs)]
	UnbalancedNumbersOfReceiveAndTransmitSublinkSpeedAttributes,
	
	#[allow(missing_docs)]
	MissingReceiveSublinkSpeedAttribute
	{
		sublink_speed_attribute_identifier: SublinkSpeedAttributeIdentifier,
	},
	
	#[allow(missing_docs)]
	MissingTransmitSublinkSpeedAttribute
	{
		sublink_speed_attribute_identifier: SublinkSpeedAttributeIdentifier,
	},
	
	#[allow(missing_docs)]
	ReceiveAndTransmitSublinkSpeedAttributesAreNotSymmetric,
	
	#[allow(missing_docs)]
	ReceiveAndTransmitSublinkSpeedAttributesHaveDifferentSymmetry,
	
	#[allow(missing_docs)]
	DuplicateSublinkSpeedAttribute
	{
		sublink_speed_attribute_identifier: SublinkSpeedAttributeIdentifier,
	},
	
	#[allow(missing_docs)]
	SublinkSpeedAttributesDoesNotContainMinimumLaneSpeed
	{
		minimum_lane_speed_sublink_speed_attribute_identifier: SublinkSpeedAttributeIdentifier
	},
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForSublinkSpeedAttributeIdentifiers(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForReceives(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForTransmits(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForSublinkSpeedAttributes(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
}

impl Display for SuperSpeedPlusDeviceCapabilityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for SuperSpeedPlusDeviceCapabilityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use SuperSpeedPlusDeviceCapabilityParseError::*;
		
		match self
		{
			CouldNotAllocateMemoryForSublinkSpeedAttributeIdentifiers(cause) => Some(cause),
			
			CouldNotAllocateMemoryForReceives(cause) => Some(cause),
			
			CouldNotAllocateMemoryForTransmits(cause) => Some(cause),
			
			CouldNotAllocateMemoryForSublinkSpeedAttributes(cause) => Some(cause),
			
			_ => None,
		}
	}
}
