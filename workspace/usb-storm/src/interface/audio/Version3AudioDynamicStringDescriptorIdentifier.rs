// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Each string can have a maximum of 65,528 bytes of UTF-16 little endian data.
///
/// The identifier is never less than 256.
///
/// A class-specific string descriptor defined in Device Class for Audio, Release 3.0-Errata, Section 4.9 Class-Spcific String Descriptors, page 104.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
#[allow(missing_docs)]
pub struct Version3AudioDynamicStringDescriptorIdentifier(NonZeroU16);

impl Version3AudioDynamicStringDescriptorIdentifier
{
	#[inline(always)]
	fn parse<E>(entity_body: &[u8], adjusted_index: usize, error: E) -> Result<Option<Self>, E>
	{
		match entity_body.optional_non_zero_u16(adjusted_index)
		{
			None => Ok(None),
			
			Some(value) if value.get() >= 256 =>
			{
				Ok(Some(Self(value)))
			}
			
			Some(_) => Err(error),
		}
	}
}
