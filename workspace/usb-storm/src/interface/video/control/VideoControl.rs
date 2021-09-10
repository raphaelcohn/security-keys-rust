// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Class-specific VC header interface descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VideoControl
{
	specification_version: Version,
	
	device_clock_frequency_in_hertz: u32,
	
	interfaces_collection: WrappedIndexSet<InterfaceNumber>,
	
	entity_descriptors: EntityDescriptors,
}

impl VideoControl
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn specification_version(&self) -> Version
	{
		self.specification_version
	}
	
	/// Deprecated as of `specification_version()` 1.1.
	/// Was last valid in `specification_version()` 1.0.
	#[inline(always)]
	pub const fn device_clock_frequency_in_hertz(&self) -> u32
	{
		self.device_clock_frequency_in_hertz
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn interfaces_collection(&self) -> &WrappedIndexSet<InterfaceNumber>
	{
		&self.interfaces_collection
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn unit_and_terminal_entities(&self) -> &EntityDescriptors
	{
		&self.entity_descriptors
	}
	
	#[inline(always)]
	fn parse(descriptor_body: &[u8], descriptor_body_length: usize, remaining_bytes: &[u8], device_connection: &DeviceConnection, video_protocol: VideoProtocol) -> Result<DeadOrAlive<(Self, usize)>, VideoControlParseError>
	{
		use VideoControlParseError::*;
		
		let (consumed_length, entity_descriptors_bytes) =
		{
			let total_length = descriptor_body.u16(descriptor_index::<5>()) as usize;
			let consumed_length = total_length - DescriptorHeaderLength;
			if unlikely!(consumed_length < descriptor_body_length)
			{
				return Err(TotalLengthLessThanHeaderDescriptor)
			}
			if unlikely!(consumed_length > remaining_bytes.len())
			{
				return Err(TotalLengthExceedsRemainingBytes)
			}
			(consumed_length, remaining_bytes.get_unchecked_range_safe(descriptor_body_length .. consumed_length))
		};
		
		let specification_version = Self::parse_specification_version(descriptor_body, video_protocol)?;
		Ok
		(
			Alive
			(
				(
					Self
					{
						specification_version,
					
						device_clock_frequency_in_hertz: descriptor_body.u32(descriptor_index::<7>()),
					
						interfaces_collection: Self::parse_interfaces_collection(descriptor_body, descriptor_body_length)?,
					
						entity_descriptors:
						{
							let dead_or_alive = EntityDescriptors::parse(entity_descriptors_bytes, device_connection, specification_version)?;
							return_ok_if_dead!(dead_or_alive)
						},
					},
					
					consumed_length,
				)
			)
		)
	}
	
	#[inline(always)]
	fn parse_specification_version(descriptor_body: &[u8], video_protocol: VideoProtocol) -> Result<Version, VideoControlParseError>
	{
		use VideoProtocol::*;
		
		use VideoControlParseError::*;
		
		let specification_version = descriptor_body.version(descriptor_index::<3>()).map_err(VersionParse)?;
		
		match (video_protocol, specification_version.is_1_5_or_greater())
		{
			(Version_1_0, false) => (),
			
			(Version_1_5, true) => (),
			
			_ => return Err(MismatchBetweenVideoProtocolAndSpecificationVersion { video_protocol, specification_version })
		}
		
		Ok(specification_version)
	}
	
	#[inline(always)]
	fn parse_interfaces_collection(descriptor_body: &[u8], descriptor_body_length: usize) -> Result<WrappedIndexSet<InterfaceNumber>, HeaderInterfacesCollectionParseError>
	{
		use HeaderInterfacesCollectionParseError::*;
		
		let number_of_interfaces_in_collection = Self::parse_number_of_interfaces_in_collection(descriptor_body, descriptor_body_length)?;
		let mut interfaces_collection = WrappedIndexSet::with_capacity(number_of_interfaces_in_collection).map_err(CouldNotAllocateInterfacesCollection)?;
		for interface_index in 0 .. number_of_interfaces_in_collection
		{
			let baInterfaceNr = descriptor_body.u8(descriptor_index_non_constant(12 + interface_index));
			if unlikely!(baInterfaceNr >= MaximumNumberOfInterfaces)
			{
				return Err(InterfaceNumberTooLarge { baInterfaceNr })
			}
			let interface_number = baInterfaceNr;
			
			let outcome = interfaces_collection.insert(interface_number);
			if unlikely!(outcome == false)
			{
				return Err(DuplicateInterfaceNumber { interface_number })
			}
		}
		Ok(interfaces_collection)
	}
	
	#[inline(always)]
	fn parse_number_of_interfaces_in_collection(descriptor_body: &[u8], descriptor_body_length: usize) -> Result<usize, HeaderInterfacesCollectionParseError>
	{
		use HeaderInterfacesCollectionParseError::*;
		
		const LastNonVariableIndex: usize = 11;
		
		let number_of_interfaces_in_collection =
		{
			let bInCollection = descriptor_body.u8(descriptor_index::<LastNonVariableIndex>());
			if unlikely!(bInCollection == 0)
			{
				return Err(ThereMustBeAtLeastOneInterfaceInTheCollection)
			}
			if unlikely!(bInCollection > MaximumNumberOfInterfaces)
			{
				return Err(TooManyInterfacesInTheCollection { bInCollection })
			}
			bInCollection as usize
		};
		if unlikely!(DescriptorHeaderLength + descriptor_body_length < (LastNonVariableIndex + number_of_interfaces_in_collection))
		{
			return Err(NotEnoughBytesForAllInterfacesInTheCollection)
		}
		Ok(number_of_interfaces_in_collection)
	}
}
