// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Mandatory for hubs.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum PlatformDeviceCapability
{
	/// See <https://wicg.github.io/webusb/>.
	WebUsb(WebUsbPlatformDeviceCapability),
	
	/// Used for Version 2.0 of Microsoft OS descriptors.
	///
	/// See download as [Microsoft OS 2.0 Descriptors Specification](https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-os-2-0-descriptors-specification).
	MicrosoftOperatingSystem(MicrosoftOperatingSystemPlatformDeviceCapability),
	
	#[allow(missing_docs)]
	Other
	{
		key: UniversallyUniqueIdentifier,
		
		value: Vec<u8>,
	}
}

impl PlatformDeviceCapability
{
	const WebUsbUniversallyUniqueIdentifier: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_microsoft_string_or_panic(b"{3408b638-09a9-47a0-8bfd-a0768815b665}");
	
	const MicrosoftOsDescriptorUniversallyUniqueIdentifier: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"D8DD60DF-4589-4CC7-9CD2-659D9E648A9F");
	
	#[inline(always)]
	pub(super) fn parse(device_capability_bytes: &[u8], device_connection: &DeviceConnection, has_microsoft_operating_system_descriptors_version_2_0: &mut bool) -> Result<DeadOrAlive<Self>, PlatformDeviceCapabilityParseError>
	{
		use PlatformDeviceCapabilityParseError::*;
		
		const MinimumSize: usize = minimum_size::<20>();
		if unlikely!(device_capability_bytes.len() < MinimumSize)
		{
			return Err(TooShort)
		}
		
		let bReserved = device_capability_bytes.u8(0);
		if unlikely!(bReserved != 0)
		{
			return Err(HasReservedByteSet)
		}
		
		let key = device_capability_bytes.universally_unique_identifier(1);
		let value_bytes = device_capability_bytes.get_unchecked_range_safe(MinimumSize .. );
		
		use PlatformDeviceCapability::*;
		Ok
		(
			Alive
			(
				match key
				{
					Self::WebUsbUniversallyUniqueIdentifier =>
					{
						let dead_or_alive = WebUsbPlatformDeviceCapability::parse(value_bytes, device_connection)?;
						WebUsb(return_ok_if_dead!(dead_or_alive))
					},
					
					Self::MicrosoftOsDescriptorUniversallyUniqueIdentifier =>
					{
						*has_microsoft_operating_system_descriptors_version_2_0 = true;
						MicrosoftOperatingSystem(MicrosoftOperatingSystemPlatformDeviceCapability::parse(value_bytes)?)
					},
					
					_ => Other
					{
						key,
						
						value: Vec::new_from(value_bytes)?,
					}
				}
			)
		)
	}
}
