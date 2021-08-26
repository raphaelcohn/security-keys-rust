// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Internet printing protocol (IPP) descriptor.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InternetPrintingProtocolInterfaceExtraDescriptor
{
	print_class_specification_release_major_version: u8,
	
	basic_capabilities: WrappedBitFlags<BasicCapability>,
	
	authentication: Authentication,
	
	versions_supported: Option<LocalizedStrings>,

	printer_uuid: Option<LocalizedStrings>,
	
	vendor_capability_descriptors: Vec<VendorCapabilityDescriptor>,
}

impl InternetPrintingProtocolInterfaceExtraDescriptor
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn print_class_specification_release_major_version(&self) -> u8
	{
		self.print_class_specification_release_major_version
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn basic_capabilities(&self) -> WrappedBitFlags<BasicCapability>
	{
		self.basic_capabilities
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn authentication(&self) -> Authentication
	{
		self.authentication
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn versions_supported(&self) -> Option<Split<char>>
	{
		Self::retrieve_solitary_string(&self.versions_supported).map(|versions_supported| versions_supported.split(','))
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn printer_uuid(&self) -> Option<&str>
	{
		Self::retrieve_solitary_string(&self.printer_uuid)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn vendor_capability_descriptors(&self) -> &[VendorCapabilityDescriptor]
	{
		&self.vendor_capability_descriptors
	}
	
	#[inline(always)]
	fn retrieve_solitary_string(strings: &Option<LocalizedStrings>) -> Option<&str>
	{
		let strings = match strings
		{
			None => return None,
			
			&Some(ref strings) => strings
		};
		
		if likely!(strings.len() <= 1)
		{
			return strings.first_value()
		}
		
		use Language::*;
		macro_rules! find_string
		{
		    ($Language: ident, $SubLanguage: ident) =>
			{
				for sub_language in $SubLanguage::iter()
				{
					if let Some(string) = strings.get(&$Language(sub_language))
					{
						return Some(string.as_str())
					}
				}
			}
		}
		find_string!(HumanInterfaceDevice, HumanInterfaceDeviceSubLanguage);
		find_string!(English, EnglishSubLanguage);
		strings.first_value()
	}
}
