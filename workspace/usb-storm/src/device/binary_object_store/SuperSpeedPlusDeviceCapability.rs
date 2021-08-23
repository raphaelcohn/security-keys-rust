// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// SuperSpeed Plus.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuperSpeedPlusDeviceCapability
{
	number_of_sublink_speed_identifiers: u4,
	
	minimum_lane_speed_sublink_speed_attribute_identifier: SublinkSpeedAttributeIdentifier,
	
	minimum_receive_lane_count: u4,
	
	minimum_transmit_lane_count: u4,
	
	sublink_speed_attributes: WrappedIndexMap<SublinkSpeedAttributeIdentifier, SublinkSpeedLinks>,
}

impl SuperSpeedPlusDeviceCapability
{
	const MinimumSize: usize = minimum_size::<12>();
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn number_of_sublink_speed_identifiers(&self) -> u4
	{
		self.number_of_sublink_speed_identifiers
	}
	
	/// Has been validated to be present in `self.sublink_speed_attributes()`.
	#[inline(always)]
	pub const fn minimum_lane_speed_sublink_speed_attribute_identifier(&self) -> SublinkSpeedAttributeIdentifier
	{
		self.minimum_lane_speed_sublink_speed_attribute_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn minimum_receive_lane_count(&self) -> u4
	{
		self.minimum_receive_lane_count
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn minimum_transmit_lane_count(&self) -> u4
	{
		self.minimum_transmit_lane_count
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn sublink_speed_attributes(&self) -> &WrappedIndexMap<SublinkSpeedAttributeIdentifier, SublinkSpeedLinks>
	{
		&self.sublink_speed_attributes
	}
	
	#[inline(always)]
	fn parse(device_capability_bytes: &[u8]) -> Result<Self, SuperSpeedPlusDeviceCapabilityParseError>
	{
		use SuperSpeedPlusDeviceCapabilityParseError::*;
		
		if unlikely!(device_capability_bytes.len() < Self::MinimumSize)
		{
			return Err(TooShort)
		}
		
		{
			let bReserved = device_capability_bytes.u8(0);
			if unlikely!(bReserved != 0)
			{
				return Err(HasReservedByteSet)
			}
		}
		
		let (number_of_sublink_speed_attributes, number_of_sublink_speed_identifiers) =
		{
			let bmAttributes = device_capability_bytes.u32(1);
			
			const ValidBits: u32 = 0b1111_1111;
			if unlikely!((bmAttributes & (!ValidBits)) != 0)
			{
				return Err(HasReservedAttributesBitsSet)
			}
			
			let sublink_speed_attribute_count = (bmAttributes & 0b1111) as u4;
			let sublink_speed_identifiers_count = ((bmAttributes & 0b1111_0000) >> 4) as u4;
			
			let number_of_sublink_speed_attributes = sublink_speed_attribute_count + 1;
			
			if unlikely!(number_of_sublink_speed_attributes % 2 != 0)
			{
				return Err(TheNumberOfSublinksIsNotPaired)
			}
			
			(number_of_sublink_speed_attributes, sublink_speed_identifiers_count + 1)
		};
		
		let (minimum_lane_speed_sublink_speed_attribute_identifier, minimum_receive_lane_count, minimum_transmit_lane_count) =
		{
			let wFunctionalitySupport = device_capability_bytes.u16(5);
			const ReservedBits: u16 = 0b1111_0000;
			if unlikely!((wFunctionalitySupport & ReservedBits) != 0)
			{
				return Err(HasReservedFunctionalitySupportBitsSet)
			}
			
			let minimum_lane_speed_sublink_speed_attribute_identifier: SublinkSpeedAttributeIdentifier = (wFunctionalitySupport & 0b1111) as u4;
			let minimum_receive_lane_count = ((wFunctionalitySupport >> 8) & 0b1111) as u4;
			let minimum_transmit_lane_count = ((wFunctionalitySupport >> 12) & 0b1111) as u4;
			
			(minimum_lane_speed_sublink_speed_attribute_identifier, minimum_receive_lane_count, minimum_transmit_lane_count)
		};
		
		{
			let wReserved = device_capability_bytes.u16(7);
			if unlikely!(wReserved != 0)
			{
				return Err(HasReservedWordSet)
			}
		}
		
		let sublink_speed_attributes = Self::parse_sublink_speed_attributes(device_capability_bytes, number_of_sublink_speed_attributes)?;
		
		if unlikely!(!sublink_speed_attributes.contains_key(&minimum_lane_speed_sublink_speed_attribute_identifier))
		{
			return Err(SublinkSpeedAttributesDoesNotContainMinimumLaneSpeed { minimum_lane_speed_sublink_speed_attribute_identifier })
		}
		
		Ok
		(
			Self
			{
				number_of_sublink_speed_identifiers,
				
				minimum_lane_speed_sublink_speed_attribute_identifier,
				
				minimum_receive_lane_count,
				
				minimum_transmit_lane_count,
				
				sublink_speed_attributes,
			}
		)
	}
	
	#[inline(always)]
	fn parse_sublink_speed_attributes(device_capabilities_bytes: &[u8], number_of_sublink_speed_attributes: u4) -> Result<WrappedIndexMap<SublinkSpeedAttributeIdentifier, SublinkSpeedLinks>, SuperSpeedPlusDeviceCapabilityParseError>
	{
		use SuperSpeedPlusDeviceCapabilityParseError::*;
		
		let sublink_speed_attributes_bytes =
		{
			let sublink_speed_attributes_bytes = device_capabilities_bytes.get_unchecked_range_safe(Self::MinimumSize..);
			let length = sublink_speed_attributes_bytes.len();
			if unlikely!(length < ((number_of_sublink_speed_attributes as usize) * Self::Scale))
			{
				return Err(NotEnoughBytesForSublinkSpeedAttributes)
			}
			sublink_speed_attributes_bytes
		};
		
		let (sublink_speed_attribute_identifiers, mut receives, mut transmits) = Self::parse_sublink_speed_attributes_inner(sublink_speed_attributes_bytes, number_of_sublink_speed_attributes)?;
		let mut sublink_speed_attributes = WrappedIndexMap::with_capacity(sublink_speed_attribute_identifiers.len()).map_err(CouldNotAllocateMemoryForSublinkSpeedAttributes)?;
		for sublink_speed_attribute_identifier in sublink_speed_attribute_identifiers.iter()
		{
			let sublink_speed_attribute_identifier = *sublink_speed_attribute_identifier;
			let (receive_symmetry, receive) = receives.remove(&sublink_speed_attribute_identifier).ok_or(MissingReceiveSublinkSpeedAttribute { sublink_speed_attribute_identifier })?;
			let (transmit_symmetry, transmit) = transmits.remove(&sublink_speed_attribute_identifier).ok_or(MissingTransmitSublinkSpeedAttribute { sublink_speed_attribute_identifier })?;
			
			use SublinkTypeSymmetry::*;
			let sublink_speed_links = match (receive_symmetry, transmit_symmetry)
			{
				(Asymmetric, Asymmetric) => SublinkSpeedLinks::Asymmetric { receive, transmit },
				
				(Symmetric, Symmetric) => if unlikely!(receive != transmit)
				{
					return Err(ReceiveAndTransmitSublinkSpeedAttributesAreNotSymmetric)
				}
				else
				{
					SublinkSpeedLinks::Symmetric(receive)
				},
				
				_ => return Err(ReceiveAndTransmitSublinkSpeedAttributesHaveDifferentSymmetry)
			};
			let outcome = sublink_speed_attributes.insert(sublink_speed_attribute_identifier, sublink_speed_links);
			if unlikely!(outcome.is_some())
			{
				return Err(DuplicateSublinkSpeedAttribute { sublink_speed_attribute_identifier })
			}
		}
		debug_assert!(sublink_speed_attributes.is_empty());
		debug_assert!(receives.is_empty());
		debug_assert!(transmits.is_empty());
		
		Ok(sublink_speed_attributes)
	}
	
	const Scale: usize = size_of::<u32>();
	
	fn parse_sublink_speed_attributes_inner(sublink_speed_attributes_bytes: &[u8], number_of_sublink_speed_attributes: u4) -> Result<(WrappedIndexSet<SublinkSpeedAttributeIdentifier>, WrappedHashMap<SublinkSpeedAttributeIdentifier, (SublinkTypeSymmetry, SublinkSpeedAttribute)>, WrappedHashMap<SublinkSpeedAttributeIdentifier, (SublinkTypeSymmetry, SublinkSpeedAttribute)>), SuperSpeedPlusDeviceCapabilityParseError>
	{
		use SuperSpeedPlusDeviceCapabilityParseError::*;
		
		let capacity = number_of_sublink_speed_attributes / 2;
		let mut sublink_speed_attribute_identifiers = WrappedIndexSet::with_capacity(capacity).map_err(CouldNotAllocateMemoryForSublinkSpeedAttributeIdentifiers)?;
		let mut receives = WrappedHashMap::with_capacity(capacity).map_err(CouldNotAllocateMemoryForReceives)?;
		let mut transmits = WrappedHashMap::with_capacity(capacity).map_err(CouldNotAllocateMemoryForTransmits)?;
		
		for sublink_speed_attribute_index in 0 .. number_of_sublink_speed_attributes
		{
			let (sublink_speed_attribute_identifier, (symmetry, receive_or_transmit), attribute) = Self::parse_sublink_speed_attribute(sublink_speed_attribute_index, sublink_speed_attributes_bytes)?;
			
			use ReceiveOrTransmit::*;
			let outcome = match receive_or_transmit
			{
				Receive => receives.insert(sublink_speed_attribute_identifier, (symmetry, attribute)),
				
				Transmit => transmits.insert(sublink_speed_attribute_identifier, (symmetry, attribute)),
			};
			
			if unlikely!(outcome.is_some())
			{
				return Err(DuplicateSublinkTypeForSublinkSpeedAttribute { sublink_speed_attribute_index })
			}
			
			let _ = sublink_speed_attribute_identifiers.insert(sublink_speed_attribute_index);
		}
		
		if unlikely!(receives.len() != transmits.len())
		{
			return Err(UnbalancedNumbersOfReceiveAndTransmitSublinkSpeedAttributes)
		}
		
		Ok((sublink_speed_attribute_identifiers, receives, transmits))
	}
	
	fn parse_sublink_speed_attribute(sublink_speed_attribute_index: u8, sublink_speed_attributes_bytes: &[u8]) -> Result<(SublinkSpeedAttributeIdentifier, SublinkType, SublinkSpeedAttribute), SuperSpeedPlusDeviceCapabilityParseError>
	{
		use SuperSpeedPlusDeviceCapabilityParseError::*;
		
		let sublink_speed_attribute_u32 = sublink_speed_attributes_bytes.u32((sublink_speed_attribute_index as usize) * Self::Scale);
		
		let sublink_speed_attribute_identifier = (sublink_speed_attribute_u32 & 0b1111) as u4;
		let lane_speed_exponent: BitRate = unsafe { transmute(((sublink_speed_attribute_u32 & 0b0011_0000) >> 4) as u2) };
		let symmetry: SublinkTypeSymmetry = unsafe { transmute(((sublink_speed_attribute_u32 & 0b0100_0000) >> 6) as u1) };
		let receive_or_transmit: ReceiveOrTransmit = unsafe { transmute(((sublink_speed_attribute_u32 & 0b1000_0000) >> 7) as u1) };
		
		const ReservedBits: u32 = 0b0011_1111_0000_0000;
		if unlikely!(sublink_speed_attribute_u32 & ReservedBits != 0)
		{
			return Err(SublinkSpeedAttributeHasReservedBits { sublink_speed_attribute_index })
		}
		
		use SublinkProtocol::*;
		let sublink_protocol = match ((sublink_speed_attribute_u32 & 0b1100_0000_0000_0000) >> 14) as u2
		{
			0 => SuperSpeed,
			
			1 => SuperSpeedPlus,
			
			sublink_protocol @ 2 | sublink_protocol @ 3 => return Err(SublinkSpeedAttributeHasReservedLinkProtocol { sublink_speed_attribute_index, sublink_protocol }),
			
			_ => unreachable!(),
		};
		
		let lane_speed_mantissa = (sublink_speed_attribute_u32 >> 16) as u16;
		
		Ok
		(
			(
				sublink_speed_attribute_identifier,
				
				(
					symmetry,
					receive_or_transmit,
				),
				
				SublinkSpeedAttribute
				{
					lane_speed_exponent,
					
					sublink_protocol,
					
					lane_speed_mantissa,
				}
			)
		)
		
	}
}
