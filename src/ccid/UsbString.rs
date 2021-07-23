// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(crate) struct UsbString
{
	ascii: Option<String>,
	
	by_language: HashMap<Language, String>
}

impl UsbString
{
	const TimeOut: Duration = Duration::from_secs(1);
	
	#[inline(always)]
	fn read(index: u8, device_handle: &DeviceHandle<impl UsbContext>, languages: &[Language]) -> Result<Self, UsbError>
	{
		// We do not error as there is no assurance that this string has an ASCII form.
		let ascii = device_handle.read_string_descriptor_ascii(index).ok();
		
		let mut by_language = HashMap::with_capacity(languages.len());
		for language in languages
		{
			let language = *language;
			let string = device_handle.read_string_descriptor(language, index, Self::TimeOut).map_err(|cause| UsbError::CouldNotReadString { cause, language, index })?;
			let _ = by_language.insert(language, string);
		}
		
		Ok
		(
			Self
			{
				ascii,
				
				by_language,
			}
		)
	}
}
