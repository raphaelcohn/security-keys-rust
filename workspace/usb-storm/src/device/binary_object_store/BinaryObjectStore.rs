// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A set of device capabilities.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub(super) struct BinaryObjectStore(Vec<DeviceCapability>);

impl Deref for BinaryObjectStore
{
	type Target = [DeviceCapability];
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl BinaryObjectStore
{
	#[inline(always)]
	pub(super) fn parse(device_connection: &DeviceConnection, reusable_buffer: &mut ReusableBuffer) -> Result<DeadOrAlive<Option<Self>>, BinaryObjectStoreParseError>
	{
		use BinaryObjectStoreParseError::*;
		
		let (remaining_bytes, _bLength) = return_ok_if_dead_or_alive_none!(get_binary_object_store_device_descriptor(device_connection.device_handle_non_null(), reusable_buffer.as_maybe_uninit_slice())?);
		
		const MinimumRemainingSize: usize = 3;
		let remaining_length = remaining_bytes.len();
		if unlikely!(remaining_length < MinimumRemainingSize)
		{
			return Err(TooShort { remaining_length })
		}
		
		let total_length = remaining_bytes.u16(0);
		let bNumDeviceCaps = remaining_bytes.u8(2);
		
		let mut device_capabilities_bytes = remaining_bytes.get_unchecked_range_safe(MinimumRemainingSize .. ((total_length as usize) - DescriptorHeaderLength));
		
		let mut device_capabilities = Vec::new_with_capacity(bNumDeviceCaps).map_err(CouldNotAllocateMemoryForDeviceCapabilities)?;
		while !device_capabilities_bytes.is_empty()
		{
			let (length, device_capability) = return_ok_if_dead!(DeviceCapability::parse(device_capabilities_bytes, device_connection).map_err(CouldNotParseDeviceCapability)?);
			device_capabilities.push_unchecked(device_capability);
			device_capabilities_bytes = device_capabilities_bytes.get_unchecked_range_safe(length .. );
		}
		
		// NOTE: We are allowed excess bytes.
		
		Ok(Alive(Some(Self(device_capabilities))))
	}
}
