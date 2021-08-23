// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A web URL.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebUrl
{
	scheme: WebUrlScheme,

	value: String,
}

impl WebUrl
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn scheme(&self) -> WebUrlScheme
	{
		self.scheme
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn value(&self) -> &str
	{
		&self.value
	}
	
	#[inline(always)]
	fn parse(descriptor_bytes: &[u8], vendor_code: u8, url_descriptor_index: NonZeroU8) -> Result<Self, GetWebUrlError>
	{
		use GetWebUrlError::*;
		
		if unlikely!(descriptor_bytes.is_empty())
		{
			return Err(TooShort { vendor_code, url_descriptor_index })
		}
		
		Ok
		(
			Self
			{
				scheme: WebUrlScheme::parse(descriptor_bytes),
			
				value:
				{
					let url_utf_8_bytes = descriptor_bytes.get_unchecked_range_safe(1 .. );
					let bytes = Vec::new_from(url_utf_8_bytes).map_err(|cause| CouldNotAllocateMemory { cause, vendor_code, url_descriptor_index })?;
					String::from_utf8(bytes).map_err(|cause| NotValidUtf8 { cause, vendor_code, url_descriptor_index })?
				},
			}
		)
	}
}
