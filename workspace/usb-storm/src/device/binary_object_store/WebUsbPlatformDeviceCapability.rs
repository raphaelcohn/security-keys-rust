// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// See [WebUSB specification](https://wicg.github.io/webusb/#webusb-platform-capability-descriptor).
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebUsbPlatformDeviceCapability
{
	version: Version,

	landing_page_url: Option<WebUrl>,
}

impl WebUsbPlatformDeviceCapability
{
	#[inline(always)]
	fn parse(value_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, WebUsbPlatformDeviceCapabilityParseError>
	{
		if unlikely!(value_bytes.len() < 4)
		{
			return Err(WebUsbPlatformDeviceCapabilityParseError::ValueBytesTooShort)
		}
		
		Ok
		(
			Alive
			(
				Self
				{
					version: Version::parse(value_bytes.u16(0))?,
					
					landing_page_url:
					{
						let vendor_code = value_bytes.u8(1);
						let url_descriptor_index = value_bytes.u8(2);
						let landing_page_url = string_finder.find_web_usb_url(vendor_code, url_descriptor_index)?;
						return_ok_if_dead!(landing_page_url)
					},
				}
			)
		)
	}
}
