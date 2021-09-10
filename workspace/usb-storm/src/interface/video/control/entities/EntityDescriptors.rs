// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Entity descriptors.
#[derive(Default, Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntityDescriptors
{
	input_terminal: Entities<InputTerminalEntity>,
	
	output_terminal: Entities<OutputTerminalEntity>,
	
	selector_unit: Entities<SelectorUnitEntity>,
	
	processing_unit: Entities<ProcessingUnitEntity>,
	
	extension_unit: Entities<ExtensionUnitEntity>,
}

impl EntityDescriptors
{
	#[inline(always)]
	pub(super) fn parse(mut entity_descriptors_bytes: &[u8], device_connection: &DeviceConnection, specification_version: Version) -> Result<DeadOrAlive<Self>, EntityDescriptorParseError>
	{
		use EntityDescriptorParseError::*;
		
		let mut unique_entity_identifiers = WrappedHashSet::empty();
		let mut entity_descriptors = Self::default();
		while !entity_descriptors_bytes.is_empty()
		{
			let (bLengthUsize, entity_identifier, bDescriptorSubType, entity_body) = Self::parse_common(entity_descriptors_bytes, &mut unique_entity_identifiers)?;
			
			let dead_or_alive = match bDescriptorSubType
			{
				VC_DESCRIPTOR_UNDEFINED => Err(UndefinedInterfaceDescriptorType),
				
				VC_HEADER => Err(HeaderInterfaceDescriptorTypeAfterHeader),
				
				VC_INPUT_TERMINAL => Self::parse_specific(bLengthUsize, entity_identifier, entity_body, device_connection, specification_version, &mut entity_descriptors.input_terminal),
				
				VC_OUTPUT_TERMINAL => Self::parse_specific(bLengthUsize, entity_identifier, entity_body, device_connection, specification_version, &mut entity_descriptors.output_terminal),
				
				VC_SELECTOR_UNIT => Self::parse_specific(bLengthUsize, entity_identifier, entity_body, device_connection, specification_version, &mut entity_descriptors.selector_unit),
				
				VC_PROCESSING_UNIT => Self::parse_specific(bLengthUsize, entity_identifier, entity_body, device_connection, specification_version, &mut entity_descriptors.processing_unit),
				
				VC_EXTENSION_UNIT => Self::parse_specific(bLengthUsize, entity_identifier, entity_body, device_connection, specification_version, &mut entity_descriptors.extension_unit),
				
				_ => Err(UnrecognizedEntityDescriptorType { bDescriptorSubType })
			}?;
			return_ok_if_dead!(dead_or_alive);
			
			entity_descriptors_bytes = entity_descriptors_bytes.get_unchecked_range_safe(bLengthUsize .. );
		}
		
		
		Ok(Alive(entity_descriptors))
	}
	
	#[inline(always)]
	fn parse_specific<E: Entity>(bLengthUsize: usize, entity_identifier: Option<EntityIdentifier>, entity_body: &[u8], device_connection: &DeviceConnection, specification_version: Version, entities: &mut Entities<E>) -> Result<DeadOrAlive<()>, EntityDescriptorParseError>
	{
		let dead_or_alive = E::parse(bLengthUsize, entity_body, device_connection, specification_version).map_err(|cause| cause.into())?;
		let entity: E = return_ok_if_dead!(dead_or_alive);
		
		match entity_identifier
		{
			None => entities.push_anonymous(entity)?,
			
			Some(entity_identifier) =>
			{
				entities.push_identified(entity, entity_identifier)?
			}
		}
		
		Ok(Alive(()))
	}
	
	#[inline(always)]
	fn parse_common<'a>(entity_descriptors_bytes: &'a [u8], unique_entity_identifiers: &mut WrappedHashSet<EntityIdentifier>) -> Result<(usize, Option<EntityIdentifier>, DescriptorSubType, &'a [u8]), CommonEntityDescriptorParseError>
	{
		use CommonEntityDescriptorParseError::*;
		
		let length = entity_descriptors_bytes.len();
		if unlikely!(length < DescriptorEntityMinimumLength)
		{
			return Err(LessThanFourByteHeader)
		}
		
		let bLength = entity_descriptors_bytes.u8(0);
		let bLengthUsize = bLength as usize;
		if unlikely!(bLengthUsize > length)
		{
			return Err(BLengthExceedsRemainingBytes)
		}
		
		let bDescriptorType = entity_descriptors_bytes.u8(1);
		if unlikely!(bDescriptorType != CS_INTERFACE)
		{
			return Err(ExpectedInterfaceDescriptorType { bDescriptorType })
		}
		
		let bDescriptorSubType = entity_descriptors_bytes.u8(2);
		
		let entity_identifier = entity_descriptors_bytes.optional_non_zero_u8(3);
		if let Some(entity_identifier) = entity_identifier
		{
			let inserted = unique_entity_identifiers.try_to_insert(entity_identifier).map_err(OutOfMemoryCheckingUniqueIdentifiedEntityDescriptor)?;
			if unlikely!(!inserted)
			{
				return Err(NonUniqueEntityIdentifier { entity_identifier })
			}
		}
		
		let entity_body = entity_descriptors_bytes.get_unchecked_range_safe(DescriptorEntityMinimumLength .. bLengthUsize);
		
		Ok((bLengthUsize, entity_identifier, bDescriptorSubType, entity_body))
	}
}
