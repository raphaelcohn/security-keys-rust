// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[doc(hidden)]
pub struct StringFinder<'a>
{
	device_handle: &'a DeviceHandle,
	
	languages: Option<Vec<(LanguageIdentifier, Language)>>,
}

impl<'a> StringFinder<'a>
{
	#[inline(always)]
	pub(crate) fn new(device_handle: &'a DeviceHandle) -> Result<DeadOrAlive<Self>, GetLanguagesError>
	{
		Ok
		(
			Alive
			(
				Self
				{
					device_handle,
					
					languages: return_ok_if_dead!(Self::get_languages(device_handle)?),
				}
			)
		)
	}
	
	#[inline(always)]
	pub(crate) fn find_string(&self, string_descriptor_index: u8) -> Result<DeadOrAlive<Option<LocalizedStrings>>, GetLocalizedStringError>
	{
		if unlikely!(string_descriptor_index == 0)
		{
			Ok(Alive(None))
		}
		else
		{
			let string_descriptor_index = new_non_zero_u8(string_descriptor_index);
			Ok(Alive(Some(return_ok_if_dead!(self.find_string_non_zero(string_descriptor_index)?))))
		}
	}
	
	#[inline(always)]
	pub(crate) fn find_string_non_zero(&self, string_descriptor_index: NonZeroU8) -> Result<DeadOrAlive<LocalizedStrings>, GetLocalizedStringError>
	{
		match self.languages
		{
			None => return Err(GetLocalizedStringError::StringIndexNonZeroButDeviceDoesNotSupportLanguages { string_descriptor_index }),
			
			Some(ref languages) =>
			{
				let mut localized_strings = BTreeMap::new();
				for language in languages
				{
					let string = return_ok_if_dead!(self.get_localized_string(string_descriptor_index, *language)?);
					let _ = localized_strings.insert(language.1, string);
				}
				Ok(Alive(LocalizedStrings(localized_strings)))
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
				let just_languages = Vec::new_populated(languages.len(), |cause| cause, |index|
				{
					let  (_, language) = languages.get_unchecked_value_safe(index);
					Ok(language)
				})?;
				Ok(Some(just_languages))
			}
		}
		
	}
	
	#[inline(always)]
	fn get_localized_string(&self, string_descriptor_index: NonZeroU8, (language_identifier, language): (LanguageIdentifier, Language)) -> Result<DeadOrAlive<String>, GetLocalizedStringError>
	{
		use GetLocalizedStringError::*;
		
		let mut buffer = MaybeUninit::uninit_array();
		let remaining_bytes = match get_string_device_descriptor_language(self.device_handle.as_non_null(), string_descriptor_index, language_identifier, &mut buffer).map_err(|cause| GetStandardUsbDescriptor { cause, string_descriptor_index, language })?
		{
			Dead => return Ok(Dead),
			
			Alive(None) => return Err(StringIndexNonZeroButDeviceDoesNotSupportGettingString { string_descriptor_index, language }),
			
			Alive(Some(remaining_bytes)) => remaining_bytes,
		};
		
		let array_length_in_bytes = remaining_bytes.len();
		const ArrayElementSize: usize = 2;
		if unlikely!(array_length_in_bytes % ArrayElementSize != 0)
		{
			return Err(NotACorrectUtf16LittleEndianSize { string_descriptor_index, language })
		}
		
		let array_length_in_u16 = array_length_in_bytes / ArrayElementSize;
		
		// Surrogate pairs encode from 2 x u16 to 4 x bytes; no change.
		// UTF-16 LE 0xFFFF encodes to three bytes; 1.5x growth.
		let maximum_number_of_utf_8_bytes = array_length_in_bytes * 3;
		
		let mut utf_8_bytes = Vec::new_with_capacity(maximum_number_of_utf_8_bytes).map_err(|cause| CouldNotAllocateString { cause, string_descriptor_index, language })?;
		let array = unsafe { from_raw_parts(remaining_bytes.as_ptr() as *const u16, array_length_in_u16) };
		for result in decode_utf16(array.iter().cloned())
		{
			let character = result.map_err(|cause| InvalidUtf16LittleEndianSequence { cause, string_descriptor_index, language })?;
			Self::encode_utf8_raw(character, &mut utf_8_bytes);
		}
		
		utf_8_bytes.shrink_to_fit();
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
			utf_8_bytes.push_unchecked(code as u8)
		}
		else if likely!(code < 0x800)
		{
			utf_8_bytes.push_unchecked((code >> 6 & 0x1F) as u8 | TAG_TWO_B);
			utf_8_bytes.push_unchecked((code & 0x3F) as u8 | TAG_CONT)
		}
		else if likely!(code < 0x10000)
		{
			utf_8_bytes.push_unchecked((code >> 12 & 0x0F) as u8 | TAG_THREE_B);
			utf_8_bytes.push_unchecked((code >> 6 & 0x3F) as u8 | TAG_CONT);
			utf_8_bytes.push_unchecked((code & 0x3F) as u8 | TAG_CONT);
		}
		else
		{
			utf_8_bytes.push_unchecked((code >> 18 & 0x07) as u8 | TAG_FOUR_B);
			utf_8_bytes.push_unchecked((code >> 12 & 0x3F) as u8 | TAG_CONT);
			utf_8_bytes.push_unchecked((code >> 6 & 0x3F) as u8 | TAG_CONT);
			utf_8_bytes.push_unchecked((code & 0x3F) as u8 | TAG_CONT);
		}
	}
	
	#[inline(always)]
	fn get_languages(device_handle: &DeviceHandle) -> Result<DeadOrAlive<Option<Vec<(LanguageIdentifier, Language)>>>, GetLanguagesError>
	{
		use GetLanguagesError::*;
		
		let mut buffer = MaybeUninit::uninit_array();
		let remaining_bytes = return_ok_if_dead_or_alive_none!(get_string_device_descriptor_languages(device_handle.as_non_null(), &mut buffer)?);
		
		let array_length_in_bytes = remaining_bytes.len();
		const ArrayElementSize: usize = 2;
		if unlikely!(array_length_in_bytes % ArrayElementSize != 0)
		{
			return Err(NotACorrectArraySize)
		}
		
		let array_length_in_u16 = array_length_in_bytes / ArrayElementSize;
		let array = unsafe { from_raw_parts(remaining_bytes.as_ptr() as *const u16, array_length_in_u16) };
		
		let mut duplicate_language_identifiers = WrappedHashSet::with_capacity(array_length_in_u16).map_err(CouldNotAllocateDuplicateLanguages)?;
		
		let languages = Vec::new_populated(array_length_in_u16, CouldNotAllocateLanguages, |index|
		{
			let language_identifier = u16::from_le(array.get_unchecked_value_safe(index));
			let language = Language::parse(language_identifier);
			
			let inserted = duplicate_language_identifiers.insert(language_identifier);
			if unlikely!(!inserted)
			{
				return Err(DuplicateLanguage { language })
			}
			
			Ok((language_identifier, language))
		})?;
		
		Ok(Alive(Some(languages)))
	}
	
	#[inline(always)]
	pub(crate) fn find_web_usb_url(&self, vendor_code: u8, url_descriptor_index: u8) -> Result<DeadOrAlive<Option<WebUrl>>, GetWebUrlError>
	{
		if unlikely!(url_descriptor_index == 0)
		{
			Ok(Alive(None))
		}
		else
		{
			self.find_web_usb_url_non_zero(vendor_code, new_non_zero_u8(url_descriptor_index))
		}
	}
	
	#[inline(always)]
	fn find_web_usb_url_non_zero(&self, vendor_code: u8, url_descriptor_index: NonZeroU8) -> Result<DeadOrAlive<Option<WebUrl>>, GetWebUrlError>
	{
		let mut buffer: [MaybeUninit<u8>; MaximumStandardUsbDescriptorLength] = MaybeUninit::uninit_array();
		let descriptor_bytes = self.find_web_usb_url_control_transfer(vendor_code, url_descriptor_index, &mut buffer).map_err(|cause| GetWebUrlError::GetStandardUsbDescriptor { cause, vendor_code, url_descriptor_index })?;
		let descriptor_bytes = return_ok_if_dead_or_alive_none!(descriptor_bytes);
		
		let web_url = WebUrl::parse(descriptor_bytes, vendor_code, url_descriptor_index)?;
		Ok(Alive(Some(web_url)))
	}
	
	#[inline(always)]
	fn find_web_usb_url_control_transfer<'b>(&self, vendor_code: u8, url_descriptor_index: NonZeroU8, buffer: &'b mut [MaybeUninit<u8>]) -> Result<DeadOrAlive<Option<&'b [u8]>>, GetStandardUsbDescriptorError>
	{
		const WEBUSB_URL: u8 = 3;
		const GET_URL: u16 = 2;
		
		let result = control_transfer_in(self.device_handle.as_non_null(), (ControlTransferRequestType::Vendor, ControlTransferRecipient::Device, vendor_code), url_descriptor_index.get() as u16, GET_URL, buffer);
		let descriptor_bytes = GetDescriptorError::parse_result(result)?;
		match StandardUsbDescriptorError::parse::<WEBUSB_URL, false>(descriptor_bytes)?
		{
			Dead => Ok(Dead),
			
			Alive(None) => Ok(Alive(None)),
			
			Alive(Some((remaining_bytes, bLength))) =>
			{
				let length = (bLength as usize) - DescriptorHeaderLength;
				Ok(Alive(Some(remaining_bytes.get_unchecked_range_safe(.. length))))
			}
		}
	}
	
}
