// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// See <https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-os-2-0-descriptors-specification>.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MicrosoftOperatingSystemPlatformDeviceCapability(WrappedIndexMap<WindowsVersion, MicrosoftOperatingSystemPlatformDeviceCapabilitySet>);

impl Deref for MicrosoftOperatingSystemPlatformDeviceCapability
{
	type Target = WrappedIndexMap<WindowsVersion, MicrosoftOperatingSystemPlatformDeviceCapabilitySet>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl MicrosoftOperatingSystemPlatformDeviceCapability
{
	#[inline(always)]
	pub(super) fn parse(value_bytes: &[u8]) -> Result<Self, MicrosoftOperatingSystemPlatformDeviceCapabilityParseError>
	{
		use MicrosoftOperatingSystemPlatformDeviceCapabilityParseError::*;
		
		const Size: usize =
		{
			const WindowsVersionSize: usize = size_of::<u32>();
			const TotalLengthSize: usize = size_of::<u16>();
			const VendorCodeSize: usize = size_of::<u8>();
			const AlternateEnumerationCodeSize: usize = size_of::<u8>();
			WindowsVersionSize + TotalLengthSize + VendorCodeSize + AlternateEnumerationCodeSize
		};
		
		let value_bytes_length = value_bytes.len();
		let remainder = value_bytes_length % Size;
		if unlikely!(remainder != 0)
		{
			return Err(ValueBytesNotAnExactArrayMultiple { value_bytes_length })
		}
		
		let count = value_bytes_length / Size;
		let mut sets = WrappedIndexMap::with_capacity(count).map_err(CanNotAllocateMemoryForArray)?;
		let mut offset = 0;
		while offset != value_bytes_length
		{
			let next_offset = offset + Size;
			let (windows_version, set) = MicrosoftOperatingSystemPlatformDeviceCapabilitySet::parse(value_bytes.get_unchecked_range_safe(offset .. next_offset))?;
			
			let outcome = sets.insert(windows_version, set);
			if unlikely!(outcome.is_some())
			{
				return Err(DuplicateWindowsVersion { windows_version })
			}
			
			offset = next_offset;
		}
		
		Ok(Self(sets))
	}
}
