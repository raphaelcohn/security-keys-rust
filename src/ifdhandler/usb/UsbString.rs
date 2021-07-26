// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsbString
{
	ascii: Option<String>,
	
	by_language: HashMap<UsbLanguage, String>
}

impl PartialOrd for UsbString
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering>
	{
		Some(self.cmp(other))
	}
}

impl Ord for UsbString
{
	#[inline(always)]
	fn cmp(&self, other: &Self) -> Ordering
	{
		self.ascii.cmp(&other.ascii)
	}
}

impl Hash for UsbString
{
	#[inline(always)]
	fn hash<H: Hasher>(&self, state: &mut H)
	{
		self.ascii.hash(state)
	}
}

impl UsbString
{
	const TimeOut: Duration = Duration::from_secs(1);
	
	#[inline(always)]
	fn read(index: u8, device_handle: &DeviceHandle<impl UsbContext>, languages: &[Language]) -> Result<Self, UsbError>
	{
		// That said, every USB device (that support string descriptors at all) is required to provide at least one supported langid on string index zero, so you could grab that, first (with langid 0), to use as a default.
		
		// We do not error as there is no assurance that this string has an ASCII form.
		let ascii = device_handle.read_string_descriptor_ascii(index).ok();
		
		let mut by_language = HashMap::with_capacity(languages.len());
		for language in languages
		{
			let language = *language;
			let string = device_handle.read_string_descriptor(language, index, Self::TimeOut).map_err(|cause| UsbError::CouldNotReadString { cause, language, index })?;
			let _ = by_language.insert(UsbLanguage::from(language), string);
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
