// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(crate) struct StringFinder<'a>
{
	device_handle: &'a DeviceHandle,
	
	languages: Option<Vec<(LanguageIdentifier, Language)>>,
}

impl<'a> StringFinder<'a>
{
	#[inline(always)]
	pub(crate) fn new(device_handle: &'a DeviceHandle) -> Result<DeadOrAlive<Self>, GetLanguagesError>
	{
		use DeadOrAlive::*;
		
		Ok
		(
			Alive
			(
				Self
				{
					device_handle,
					
					languages: match Self::get_languages(device_handle)?
					{
						Alive(languages) => languages,
						
						Dead => return Ok(Dead)
					}
				}
			)
		)
	}
	
	#[inline(always)]
	pub(crate) fn find_string(&self, string_descriptor_index: u8) -> Result<DeadOrAlive<Option<LocalizedStrings>>, GetLocalizedStringError>
	{
		use DeadOrAlive::*;
		
		if unlikely!(string_descriptor_index == 0)
		{
			Ok(Alive(None))
		}
		else
		{
			let string_descriptor_index = new_non_zero_u8(string_descriptor_index);
			
			match self.languages
			{
				None => return Err(GetLocalizedStringError::StringIndexNonZeroButDeviceDoesNotSupportLanguages { string_descriptor_index }),
				
				Some(ref languages) =>
				{
					let mut localized_strings = HashMap::with_capacity(languages.len());
					for language in languages
					{
						let string = match self.get_localized_string(string_descriptor_index, *language)?
						{
							Dead => return Ok(Dead),
							
							Alive(string) => string,
						};
						let _ = localized_strings.insert(language.1, string);
					}
					Ok(Alive(Some(LocalizedStrings(localized_strings))))
				}
			}
			
		}
	}
	
	#[inline(always)]
	pub(crate) fn into_languages(self) -> Result<Option<Vec<Language>>, TryReserveError>
	{
		match self.languages
		{
			None => return Ok(None),
			
			Some(languages) =>
			{
				let mut just_languages = Vec::new_with_capacity(languages.len())?;
				for (_, language) in languages
				{
					just_languages.push(language)
				}
				Ok(Some(just_languages))
			}
		}
		
	}
	
	#[inline(always)]
	fn get_localized_string(&self, string_descriptor_index: NonZeroU8, (language_identifier, language): (LanguageIdentifier, Language)) -> Result<DeadOrAlive<String>, GetLocalizedStringError>
	{
		use ControlTransferError::*;
		use DeadOrAlive::*;
		use GetLocalizedStringError::*;
		use GetStandardUsbDescriptorError::ControlTransfer;
		
		let mut buffer = MaybeUninit::uninit_array();
		let remaining_bytes = match get_string_device_descriptor_language(self.device_handle.as_non_null(), &mut buffer, string_descriptor_index, language_identifier)
		{
			Ok(remaining_bytes) => remaining_bytes,
			
			Err(ControlTransfer(TransferInputOutputErrorOrTransferCancelled)) => return Ok(Dead),
			
			Err(ControlTransfer(DeviceDisconnected)) => return Ok(Dead),
			
			Err(ControlTransfer(RequestedResourceNotFound)) => panic!("Should not occur for GET_DESCRIPTOR"),
			
			Err(ControlTransfer(TimedOut)) => return Ok(Dead),
			
			Err(ControlTransfer(ControlRequestNotSupported { .. })) => return Err(StringIndexNonZeroButDeviceDoesNotSupportGettingString { string_descriptor_index, language }),
			
			Err(ControlTransfer(OutOfMemory)) => return Err(ControlRequestOutOfMemory),
			
			Err(ControlTransfer(Other)) => return Err(ControlRequestOther),
			
			Err(ControlTransfer(BufferOverflow)) => return Err(ControlRequestBufferOverflow),
			
			Err(GetStandardUsbDescriptorError::StandardUsbDescriptor(cause)) => return Err(StandardUsbDescriptor(cause)),
		};
		
		let array_length_in_bytes = remaining_bytes.len();
		const ArrayElementSize: usize = 2;
		if unlikely!(array_length_in_bytes % ArrayElementSize != 0)
		{
			return Err(NotACorrectUtf16LittleEndianSize)
		}
		
		let array_length_in_u16 = array_length_in_bytes / ArrayElementSize;
		
		// Surrogate pairs encode from 2 x u16 to 4 x bytes; no change.
		// UTF-16 LE 0xFFFF encodes to three bytes; 1.5x growth.
		let maximum_number_of_utf_8_bytes = array_length_in_bytes * 3;
		let mut utf_8_bytes = Vec::new_with_capacity(maximum_number_of_utf_8_bytes).map_err(CouldNotAllocateString)?;
		
		let array = unsafe { from_raw_parts(remaining_bytes.as_ptr() as *const u16, array_length_in_u16) };
		for result in decode_utf16(array.iter().cloned())
		{
			let character = result.map_err(InvalidUtf16LittleEndianSequence)?;
			Self::encode_utf8_raw(character, &mut utf_8_bytes);
		}
		
		Ok(Alive(unsafe { String::from_utf8_unchecked(utf_8_bytes) }))
	}
	
	#[inline(always)]
	fn encode_utf8_raw(character: char, utf_8_bytes: &mut Vec<u8>)
	{
		const TAG_CONT: u8 = 0b1000_0000;
		const TAG_TWO_B: u8 = 0b1100_0000;
		const TAG_THREE_B: u8 = 0b1110_0000;
		const TAG_FOUR_B: u8 = 0b1111_0000;
		
		let code = character as u32;
		if likely!(code < 0x80)
		{
			utf_8_bytes.push(code as u8)
		}
		else if likely!(code < 0x800)
		{
			utf_8_bytes.push((code >> 6 & 0x1F) as u8 | TAG_TWO_B);
			utf_8_bytes.push((code & 0x3F) as u8 | TAG_CONT)
		}
		else if likely!(code < 0x10000)
		{
			utf_8_bytes.push((code >> 12 & 0x0F) as u8 | TAG_THREE_B);
			utf_8_bytes.push((code >> 6 & 0x3F) as u8 | TAG_CONT);
			utf_8_bytes.push((code & 0x3F) as u8 | TAG_CONT);
		}
		else
		{
			utf_8_bytes.push((code >> 18 & 0x07) as u8 | TAG_FOUR_B);
			utf_8_bytes.push((code >> 12 & 0x3F) as u8 | TAG_CONT);
			utf_8_bytes.push((code >> 6 & 0x3F) as u8 | TAG_CONT);
			utf_8_bytes.push((code & 0x3F) as u8 | TAG_CONT);
		}
	}
	
	#[inline(always)]
	fn get_languages(device_handle: &DeviceHandle) -> Result<DeadOrAlive<Option<Vec<(LanguageIdentifier, Language)>>>, GetLanguagesError>
	{
		use ControlTransferError::*;
		use DeadOrAlive::*;
		use GetLanguagesError::*;
		use GetStandardUsbDescriptorError::ControlTransfer;
		
		let mut buffer = MaybeUninit::uninit_array();
		let remaining_bytes = match get_string_device_descriptor_languages(device_handle.as_non_null(), &mut buffer)
		{
			Ok(remaining_bytes) => remaining_bytes,
			
			Err(ControlTransfer(TransferInputOutputErrorOrTransferCancelled)) => return Ok(Dead),
			
			Err(ControlTransfer(DeviceDisconnected)) => return Ok(Dead),
			
			Err(ControlTransfer(RequestedResourceNotFound)) => panic!("Should not occur for GET_DESCRIPTOR"),
			
			Err(ControlTransfer(TimedOut)) => return Ok(Dead),
			
			Err(ControlTransfer(ControlRequestNotSupported { .. })) => return Ok(Alive(None)),
			
			Err(ControlTransfer(OutOfMemory)) => return Err(ControlRequestOutOfMemory),
			
			Err(ControlTransfer(Other)) => return Err(ControlRequestOther),
			
			Err(ControlTransfer(BufferOverflow)) => return Err(ControlRequestBufferOverflow),
			
			Err(GetStandardUsbDescriptorError::StandardUsbDescriptor(cause)) => return Err(StandardUsbDescriptor(cause)),
		};
		
		let array_length_in_bytes = remaining_bytes.len();
		const ArrayElementSize: usize = 2;
		if unlikely!(array_length_in_bytes % ArrayElementSize != 0)
		{
			return Err(NotACorrectArraySize)
		}
		
		let array_length_in_u16 = array_length_in_bytes / ArrayElementSize;
		let array = unsafe { from_raw_parts(remaining_bytes.as_ptr() as *const u16, array_length_in_u16) };
		
		let mut languages = Vec::new_with_capacity(array_length_in_u16).map_err(CouldNotAllocateLanguages)?;
		for index in 0 .. array_length_in_u16
		{
			let language_identifier = u16::from_le(array.get_unchecked_value_safe(index));
			let language = Language::parse(language_identifier);
			
			if unlikely!(languages.contains(&(language_identifier, language)))
			{
				return Err(DuplicateLanguage { language })
			}
			
			languages.push((language_identifier, language))
		}
		
		Ok(Alive(Some(languages)))
	}
}
