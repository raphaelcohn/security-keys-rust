// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Class-specific AC interface descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum AudioControlInterfaceExtraDescriptor
{
	/// See Device Class for Audio Release 1.0, Section 4.3.2 Class-Specific AC Interface Descriptor, page 37.
	Version_1_0
	{
		#[allow(missing_docs)]
		entity_descriptors: Version1EntityDescriptors,
		
		/// A bit useless, as we need to know the version in advance before we start parsing to find the version field!
		audio_device_class_specification_release: Version,
		
		#[allow(missing_docs)]
		interface_numbers: WrappedIndexSet<InterfaceNumber>,
	},
	
	/// See Device Class for Audio Release 2.0, Section 4.7.2 Class-Specific AC Interface Descriptor, page 48.
	Version_2_0
	{
		#[allow(missing_docs)]
		function_category: AudioFunctionCategory,
		
		#[allow(missing_docs)]
		latency_control: Control,
		
		#[allow(missing_docs)]
		entity_descriptors: Version2EntityDescriptors,
		
		/// A bit useless, as we need to know the version in advance before we start parsing to find the version field!
		audio_device_class_specification_release: Version,
	},
	
	/// See page 68 of Device Class for Audio, Release 3.0-Errata.
	Version_3_0
	{
		#[allow(missing_docs)]
		function_category: AudioFunctionCategory,
		
		#[allow(missing_docs)]
		latency_control: Control,
		
		#[allow(missing_docs)]
		entity_descriptors: Version3EntityDescriptors,
	},
	
	/// Unrecognized.
	Unrecognised
	{
		#[allow(missing_docs)]
		protocol: u8,
		
		#[allow(missing_docs)]
		bLength: u8,
		
		#[allow(missing_docs)]
		remaining_bytes: Vec<u8>,
	}
}

impl AudioControlInterfaceExtraDescriptor
{
	#[inline(always)]
	fn parse_descriptor_version_1_0(string_finder: &StringFinder, bLength: u8, remaining_bytes: &[u8]) -> Result<DeadOrAlive<(Self, usize)>, AudioControlInterfaceExtraDescriptorParseError>
	{
		use AudioControlInterfaceExtraDescriptorParseError::*;
		
		const MinimumBLength: u8 = 8;
		let (descriptor_body, descriptor_body_length, audio_device_class_specification_release) = Self::parse_descriptor_header_and_version::<MinimumBLength>(bLength, remaining_bytes)?;
		
		let total_length_excluding_header = Self::total_length_excluding_header(descriptor_body.u16(3), remaining_bytes)?;
		
		const InterfaceBaseIndex: usize = 5;
		let bInCollection = descriptor_body.u8(InterfaceBaseIndex);
		
		let mut interface_numbers = WrappedIndexSet::with_capacity(bInCollection).map_err(CouldNotAllocateMemoryForInterfaceNumbers)?;
		const InterfaceFirstIndex: usize = InterfaceBaseIndex + size_of::<u8>();
		for index in 0 .. bInCollection
		{
			let interface_number = descriptor_body.u8(InterfaceFirstIndex + (index as usize));
			if unlikely!(interface_number >= MaximumNumberOfInterfaces)
			{
				return Err(Version1InterfaceNumberTooBig { index, interface_number } )
			}
			let inserted = interface_numbers.insert(interface_number);
			if unlikely!(inserted == false)
			{
				return Err(Version1InterfaceNumberDuplicated { index, interface_number } )
			}
		}
		
		Self::ok_alive
		(
			AudioControlInterfaceExtraDescriptor::Version_1_0
			{
				entity_descriptors:
				{
					let entity_descriptors = Self::parse_entities(string_finder, remaining_bytes, descriptor_body_length, total_length_excluding_header)?;
					return_ok_if_dead!(entity_descriptors)
				},
				
				audio_device_class_specification_release,
				
				interface_numbers,
			},
			
			total_length_excluding_header,
		)
	}
	
	#[inline(always)]
	fn parse_descriptor_version_2_0(string_finder: &StringFinder, bLength: u8, remaining_bytes: &[u8]) -> Result<DeadOrAlive<(Self, usize)>, AudioControlInterfaceExtraDescriptorParseError>
	{
		const MinimumBLength: u8 = 9;
		let (descriptor_body, descriptor_body_length, audio_device_class_specification_release) = Self::parse_descriptor_header_and_version::<MinimumBLength>(bLength, remaining_bytes)?;
		
		let function_category = Self::parse_category(descriptor_body.u8(3));
		
		let total_length_excluding_header = Self::total_length_excluding_header(descriptor_body.u16(4), remaining_bytes)?;
		
		let bmControls = descriptor_body.u8(6);
		let latency_control = Control::parse_u8(bmControls, 0, AudioControlInterfaceExtraDescriptorParseError::ParseVersion2Entity(EntityDescriptorParseError::Version(Version2EntityDescriptorParseError::LatencyControlInvalid)))?;
		
		Self::ok_alive
		(
			AudioControlInterfaceExtraDescriptor::Version_2_0
			{
				entity_descriptors:
				{
					let entity_descriptors = Self::parse_entities(string_finder, remaining_bytes, descriptor_body_length, total_length_excluding_header)?;
					return_ok_if_dead!(entity_descriptors)
				},
				
				audio_device_class_specification_release,
				
				latency_control,
			
				function_category,
			},
			
			total_length_excluding_header,
		)
	}
	
	#[inline(always)]
	fn parse_descriptor_version_3_0(string_finder: &StringFinder, bLength: u8, remaining_bytes: &[u8]) -> Result<DeadOrAlive<(Self, usize)>, AudioControlInterfaceExtraDescriptorParseError>
	{
		const MinimumBLength: u8 = 10;
		let (descriptor_body, descriptor_body_length) = Self::parse_descriptor_header::<MinimumBLength>(bLength, remaining_bytes)?;
		
		let function_category = Self::parse_category(descriptor_body.u8(1));
		
		let total_length_excluding_header = Self::total_length_excluding_header(descriptor_body.u16(2), remaining_bytes)?;
		
		let bmControls = descriptor_body.u32(4);
		let latency_control = Control::parse_u32(bmControls, 0, AudioControlInterfaceExtraDescriptorParseError::ParseVersion3Entity(EntityDescriptorParseError::Version(Version3EntityDescriptorParseError::LatencyControlInvalid)))?;
		Self::ok_alive
		(
			AudioControlInterfaceExtraDescriptor::Version_3_0
			{
				function_category,
				
				latency_control,
			
				entity_descriptors: return_ok_if_dead!(Self::parse_entities(string_finder, remaining_bytes, descriptor_body_length, total_length_excluding_header)?),
			},
			
			total_length_excluding_header,
		)
	}
	
	#[inline(always)]
	fn parse_descriptor_version_unrecognized(bLength: u8, remaining_bytes: &[u8], protocol: u8) -> Result<DeadOrAlive<(Self, usize)>, AudioControlInterfaceExtraDescriptorParseError>
	{
		use AudioControlInterfaceExtraDescriptorParseError::*;
		
		const MinimumBLength: u8 = MinimumStandardUsbDescriptorLength as u8;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		Self::ok_alive
		(
			AudioControlInterfaceExtraDescriptor::Unrecognised
			{
				protocol,
				
				bLength,
				
				remaining_bytes: Vec::new_from(descriptor_body).map_err(CouldNotAllocateMemoryForUnrecognized)?,
			},
			
			descriptor_body_length,
		)
	}
	
	#[inline(always)]
	const fn ok_alive(descriptor: Self, consumed_length: usize) -> Result<DeadOrAlive<(Self, usize)>, AudioControlInterfaceExtraDescriptorParseError>
	{
		Ok(Alive((descriptor, consumed_length)))
	}
	
	#[inline(always)]
	fn parse_descriptor_header_and_version<const MinimumBLength: u8>(bLength: u8, remaining_bytes: &[u8]) -> Result<(&[u8], usize, Version), AudioControlInterfaceExtraDescriptorParseError>
	{
		let (descriptor_body, descriptor_body_length) = Self::parse_descriptor_header::<MinimumBLength>(bLength, remaining_bytes)?;
		let version = descriptor_body.version(1)?;
		Ok((descriptor_body, descriptor_body_length, version))
	}
	
	#[inline(always)]
	fn parse_descriptor_header<const MinimumBLength: u8>(bLength: u8, remaining_bytes: &[u8]) -> Result<(&[u8], usize), AudioControlInterfaceExtraDescriptorParseError>
	{
		use AudioControlInterfaceExtraDescriptorParseError::*;
		
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		debug_assert!(descriptor_body_length > 0);
		let bDescriptorSubType = descriptor_body.u8(0);
		
		/// Fortuantely, this has the same value in all three versions of the specification.
		const HEADER: u8 = 0x01;
		match bDescriptorSubType
		{
			HEADER => (),
			
			_ => return Err(ExpectedHeaderDescriptorSubtype),
		}
		
		Ok((descriptor_body, descriptor_body_length))
	}
	
	#[inline(always)]
	fn parse_category(bCategory: u8) -> AudioFunctionCategory
	{
		use AudioFunctionCategory::*;
		
		match bCategory
		{
			0x00 => FunctionSubclassUndefined,
			
			0x01 => DesktopSpeaker,
			
			0x02 => HomeTheatre,
			
			0x03 => Microphone,
			
			0x04 => Headset,
			
			0x05 => Telephone,
			
			0x06 => Converter,
			
			0x07 => VoiceOrSoundRecorder,
			
			0x08 => InputOutputBox,
			
			0x09 => MusicalInstrutment,
			
			0x0A => ProAudio,
			
			0x0B => AudioOrVideo,
			
			0x0C => ControlPanell,
			
			0x0D => Headphone,
			
			0x0E => GenericSpeaker,
			
			0x0F => HeadsetAdapter,
			
			0x10 => Speakerphone,
			
			reserved @ 0x11 ..= 0xFE => Reserved(reserved),
			
			0xFF => Other,
		}
	}
	
	#[inline(always)]
	fn total_length_excluding_header(wTotalLength: u16, remaining_bytes: &[u8]) -> Result<usize, AudioControlInterfaceExtraDescriptorParseError>
	{
		let expected_length = remaining_bytes.len() + DescriptorHeaderLength;
		let wTotalLengthUsize = wTotalLength as usize;
		if unlikely!(expected_length < wTotalLengthUsize)
		{
			return Err(AudioControlInterfaceExtraDescriptorParseError::wTotalLengthExceedsRemainingBytes { expected_length, wTotalLength })
		}
		Ok(wTotalLengthUsize - DescriptorHeaderLength)
	}
	
	#[inline(always)]
	fn parse_entities<ED: EntityDescriptors<Error=E>, E: error::Error>(string_finder: &StringFinder, remaining_bytes: &[u8], descriptor_body_length: usize, total_length_excluding_header: usize) -> Result<DeadOrAlive<ED>, EntityDescriptorParseError<E>>
	{
		use EntityDescriptorParseError::*;
		
		const AC_DESCRIPTOR_UNDEFINED: u8 = 0x00;
		const HEADER: u8 = 0x01;
		
		let mut unique_entity_identifiers = WrappedHashSet::empty();
		
		let mut entity_descriptors_bytes = remaining_bytes.get_unchecked_range_safe(descriptor_body_length .. total_length_excluding_header);
		let mut entity_descriptors = ED::default();
		while !entity_descriptors_bytes.is_empty()
		{
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
			if unlikely!(bDescriptorType != AudioControlInterfaceExtraDescriptorParser::CS_INTERFACE)
			{
				return Err(ExpectedInterfaceDescriptorType)
			}
			
			let entity_identifier = entity_descriptors_bytes.optional_non_zero_u8(3);
			if let Some(entity_identifier) = entity_identifier
			{
				let inserted = unique_entity_identifiers.try_to_insert(entity_identifier).map_err(OutOfMemoryCheckingUniqueIdentifiedEntityDescriptor)?;
				if unlikely!(!inserted)
				{
					return Err(NonUniqueEntityIdentifier { entity_identifier })
				}
			}
			
			let bDescriptorSubtype = entity_descriptors_bytes.u8(2);
			
			match entity_descriptors.parse_entity_body(bLength, bDescriptorSubtype, entity_identifier, entity_descriptors_bytes.get_unchecked_range_safe(DescriptorEntityMinimumLength .. bLengthUsize), string_finder)?
			{
				Alive(true) => (),
				
				Alive(false) => return match bDescriptorSubtype
				{
					AC_DESCRIPTOR_UNDEFINED => Err(UndefinedInterfaceDescriptorType),
					
					HEADER => Err(HeaderInterfaceDescriptorTypeAfterHeader),
					
					_ => Err(UnrecognizedEntityDescriptorType)
				},
				
				Dead => return Ok(Dead),
			}
			
			entity_descriptors_bytes = entity_descriptors_bytes.get_unchecked_range_safe((bLength as usize) .. );
		}
		
		Ok(Alive(entity_descriptors))
	}
}
