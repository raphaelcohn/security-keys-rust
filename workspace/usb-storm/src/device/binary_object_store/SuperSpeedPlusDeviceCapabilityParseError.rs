// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A parse error.
#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(missing_docs)]
pub enum SuperSpeedPlusDeviceCapabilityParseError
{
	TooShort,
	
	HasReservedByteSet,
	
	HasReservedAttributesBitsSet,
	
	TheNumberOfSublinksIsNotPaired,
	
	HasReservedFunctionalitySupportBitsSet,
	
	HasReservedWordSet,
	
	NotEnoughBytesForSublinkSpeedAttributes,
	
	SublinkSpeedAttributeHasReservedBits
	{
		sublink_speed_attribute_index: u4,
	},

	SublinkSpeedAttributeHasReservedLinkProtocol
	{
		sublink_speed_attribute_index: u4,

		/// Only possible values are 2 and 3.
		sublink_protocol: u2,
	},
	
	DuplicateSublinkTypeForSublinkSpeedAttribute
	{
		sublink_speed_attribute_index: u4,
	},
	
	UnbalancedNumbersOfReceiveAndTransmitSublinkSpeedAttributes,
	
	MissingReceiveSublinkSpeedAttribute
	{
		sublink_speed_attribute_identifier: SublinkSpeedAttributeIdentifier,
	},
	
	MissingTransmitSublinkSpeedAttribute
	{
		sublink_speed_attribute_identifier: SublinkSpeedAttributeIdentifier,
	},
	
	ReceiveAndTransmitSublinkSpeedAttributesAreNotSymmetric,
	
	ReceiveAndTransmitSublinkSpeedAttributesHaveDifferentSymmetry,
	
	DuplicateSublinkSpeedAttribute
	{
		sublink_speed_attribute_identifier: SublinkSpeedAttributeIdentifier,
	},
	
	SublinkSpeedAttributesDoesNotContainMinimumLaneSpeed
	{
		minimum_lane_speed_sublink_speed_attribute_identifier: SublinkSpeedAttributeIdentifier
	},
	
	CouldNotAllocateMemoryForSublinkSpeedAttributeIdentifiers(TryReserveError),
	
	CouldNotAllocateMemoryForReceives(TryReserveError),
	
	CouldNotAllocateMemoryForTransmits(TryReserveError),
	
	CouldNotAllocateMemoryForSublinkSpeedAttributes(TryReserveError),
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
