// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[doc(hidden)]
#[derive(Debug)]
pub struct DeviceConnection<'a>
{
	device_handle: &'a DeviceHandle,
	
	languages: Option<Vec<(LanguageIdentifier, Language)>>,
}

impl<'a> DeviceConnection<'a>
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
					
					languages:
					{
						let dead_or_alive = get_languages(device_handle.as_non_null())?;
						return_ok_if_dead!(dead_or_alive)
					},
				}
			)
		)
	}
	
	#[inline(always)]
	fn into_languages(self) -> Result<Option<Vec<Language>>, TryReserveError>
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
	pub(crate) fn device_handle_non_null(&self) -> NonNull<libusb_device_handle>
	{
		self.device_handle.as_non_null()
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
			let dead_or_alive = self.find_string_non_zero(string_descriptor_index)?;
			Ok(Alive(Some(return_ok_if_dead!(dead_or_alive))))
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
					let dead_or_alive = get_localized_string(self.device_handle_non_null(), string_descriptor_index, *language)?;
					let string = return_ok_if_dead!(dead_or_alive);
					let _ = localized_strings.insert(language.1, string);
				}
				Ok(Alive(LocalizedStrings::new(localized_strings)))
			}
		}
	}
	
	/// This is very similar to finding a string, but it can contain UTF-16 little endian invalid data (a lone surrogate pair for the final character).
	#[inline(always)]
	pub(crate) fn find_microsoft_operating_system_descriptor_string_version_1_0_vendor_code(&self) -> Result<DeadOrAlive<Option<MicrosoftVendorCode>>, GetLocalizedUtf16LittleEndianStringError>
	{
		#[inline(always)]
		const fn utf16_little_endian(byte: u8) -> u16
		{
			(byte as u16).to_le()
		}
		
		const StringDescriptorIndex: NonZeroU8 = new_non_zero_u8(0xEE);
		const Languages: (u16, Language) = (0, Language::MicrosoftOperatingSystemDescriptorsVersion_1_0);
		
		const SignatureLength: usize = 14;
		const Utf16SignatureLength: usize = SignatureLength / size_of::<u16>();
		static Signature: [u16; Utf16SignatureLength] =
		[
			utf16_little_endian(b'M'),
			utf16_little_endian(b'S'),
			utf16_little_endian(b'F'),
			utf16_little_endian(b'T'),
			utf16_little_endian(b'1'),
			utf16_little_endian(b'0'),
			utf16_little_endian(b'0'),
		];
		const U16ArrayLength: usize = Utf16SignatureLength + 1;
		
		let mut buffer = MaybeUninit::uninit_array();
		let dead_or_alive = get_localized_string_utf16_little_endian(self.device_handle_non_null(), StringDescriptorIndex, Languages, &mut buffer)?;
		let (remaining_bytes, array_length_in_u16) = return_ok_if_dead_or_alive_none!(dead_or_alive);
		
		if unlikely!(array_length_in_u16 != U16ArrayLength)
		{
			return Ok(Alive(None))
		}
		
		let qwSignature = unsafe { & * (remaining_bytes.as_ptr() as *const [u16; Utf16SignatureLength]) };
		if unlikely!(qwSignature.ne(&Signature))
		{
			return Ok(Alive(None))
		}
		
		let bMS_VendorCode = remaining_bytes.get_unchecked_value_safe(SignatureLength + 1);
		Ok(Alive(Some(bMS_VendorCode)))
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
		let descriptor_bytes = find_web_usb_url_control_transfer(self.device_handle_non_null(), vendor_code, url_descriptor_index, &mut buffer).map_err(|cause| GetWebUrlError::GetStandardUsbDescriptor { cause, vendor_code, url_descriptor_index })?;
		let descriptor_bytes = return_ok_if_dead_or_alive_none!(descriptor_bytes);
		
		let web_url = WebUrl::parse(descriptor_bytes, vendor_code, url_descriptor_index)?;
		Ok(Alive(Some(web_url)))
	}
}
