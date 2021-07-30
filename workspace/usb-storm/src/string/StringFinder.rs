// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(crate) struct StringFinder
{
	device_handle: NonNull<libusb_device_handle>,

	languages: Vec<(LanguageIdentifier, Language)>,
}

impl StringFinder
{
	#[inline(always)]
	fn new(device: X) -> Self
	{
		use self::StringFinder::*;
		
		match device.open()
		{
			Err(_) => FailedToOpenDeviceHandle,
			
			Ok(device_handle) =>
			{
				let mut buffer = MaybeUninit::uninit_array();
				// Experimentation shows that `GetDescriptorError::ControlTransfer(ControlTransferError::ControlRequestNotSupported)` can occur.
				let result = match get_string_device_descriptor_languages(device_handle, &mut buffer)
				{
					Ok(bytes) => (),
					
					Err(GetDescriptorError::ControlTransfer)
				}
				
				Opened
				{
					// Experimentation shows `read_languages()` can error with `Pipe`.
					languages: device_handle.read_languages(Self::TimeOut).unwrap_or(Vec::new()),
					
					device_handle,
				}
			}
		}
	}
	
	#[inline(always)]
	pub(crate) fn find_string(&self, string_descriptor_index: u8) -> Result<LocalizedStrings, GetLocalizedStringError>
	{
		use self::StringFinder::*;
		use self::StringOrIndex::*;
		
		if unlikely!(index == 0)
		{
			Ok(None)
		}
		else
		{
			let mut localized_strings = HashMap::with_capacity(self.languages.len());
			for language in self.language_identifiers
			{
				let string = self.get_localized_string(new_non_zero_u8(string_descriptor_index), language);
			}
			Ok(localized_strings)
		}
	}
	
	#[inline(always)]
	fn get_localized_string(&self, string_descriptor_index: NonZeroU8, (language_identifier, language): (LanguageIdentifier, Language)) -> Result<Option<String>, GetLocalizedStringError>
	{
		use ControlTransferError::*;
		use GetLocalizedStringError::*;
		use GetStandardUsbDescriptorError::ControlTransfer;
		
		#[inline(always)]
		const fn get_string_device_dead() -> Option<String>
		{
			None
		}
		
		let mut buffer = MaybeUninit::uninit_array();
		let remaining_bytes = match get_string_device_descriptor_language(self.device_handle, &mut buffer, string_descriptor_index, language_identifier)
		{
			Ok(remaining_bytes) => remaining_bytes,
			
			Err(ControlTransfer(TransferInputOutputErrorOrTransferCancelled)) => return Ok(get_string_device_dead()),
			
			Err(ControlTransfer(DeviceDisconnected)) => return Ok(get_string_device_dead()),
			
			Err(ControlTransfer(TimedOut(..))) => return Ok(get_string_device_dead()),
			
			Err(ControlTransfer(ControlRequestNotSupported)) => return Err(StringIndexNonZeroButDeviceDoesNotSupportGettingString { string_descriptor_index, language }),
			
			Err(ControlTransfer(OutOfMemory)) => return Err(ControlRequestOutOfMemory),
			
			Err(ControlTransfer(NewlyDefined(error_code))) => return Err(ControlRequestNewlyDefined(error_code)),
			
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
		let utf_8_bytes = Vec::new_with_capacity(maximum_number_of_utf_8_bytes).map_err(CouldNotAllocateString)?;
		
		let array = unsafe { from_raw_parts(remaining_bytes.as_ptr() as *const u16, array_length_in_u16) };
		for result in decode_utf16(array)
		{
			let character = result?;
			Self::encode_utf8_raw(character, &mut utf_8_bytes);
		}
		
		Ok(Some(unsafe { String::from_utf8_unchecked(utf_8_bytes) }))
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
	fn get_languages(device_handle: NonNull<libusb_device_handle>) -> Result<Vec<(LanguageIdentifier, Language)>, GetLanguagesError>
	{
		use ControlTransferError::*;
		use GetLanguagesError::*;
		use GetStandardUsbDescriptorError::ControlTransfer;
		
		#[inline(always)]
		const fn get_languages_device_dead() -> Vec<(LanguageIdentifier, Language)>
		{
			Vec::new()
		}
		
		let mut buffer = MaybeUninit::uninit_array();
		let remaining_bytes = match get_string_device_descriptor_languages(device_handle, &mut buffer)
		{
			Ok(remaining_bytes) => remaining_bytes,
			
			Err(ControlTransfer(TransferInputOutputErrorOrTransferCancelled)) => return Ok(get_languages_device_dead()),
			
			Err(ControlTransfer(DeviceDisconnected)) => return Ok(get_languages_device_dead()),
			
			Err(ControlTransfer(TimedOut(..))) => return Ok(get_languages_device_dead()),
			
			Err(ControlTransfer(ControlRequestNotSupported)) => return Ok(Vec::new()),
			
			Err(ControlTransfer(OutOfMemory)) => return Err(ControlRequestOutOfMemory),
			
			Err(ControlTransfer(NewlyDefined(error_code))) => return Err(ControlRequestNewlyDefined(error_code)),
			
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
			languages.push((language_identifier, language))
		}
		
		Ok(languages)
	}
}
