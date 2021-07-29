// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn get_descriptor<const request_type: ControlTransferRequestType, const recipient: ControlTransferRecipient>(device_handle: NonNull<libusb_device_handle>, buffer: &mut [MaybeUninit<u8>; MaximumUsbDescriptorLength], descriptor_type: DescriptorType, descriptor_index: u8, index: u16) -> Result<&[u8], GetDescriptorError>
{
	use self::GetDescriptorError::*;
	
	const TimeOut: Duration = Duration::from_millis(1_000);
	
	let descriptor_type = (descriptor_type as u16) << 8;
	let value = descriptor_type | (descriptor_index as u16);
	
	let descriptor_bytes = control_transfer::<Direction::In, ControlTransferRequestType::Standard, recipient, Request::GetDescriptor>(device_handle, TimeOut, value, index, buffer)?;
	
	let length = descriptor_bytes.len() as usize;
	if unlikely!(length < MinimumUsbDescriptorLength)
	{
		return Err(TooShort)
	}
	
	let bLength = descriptor_bytes.get_unchecked_value_safe(0) as usize;
	if unlikely!(bLength > length)
	{
		return Err(LengthMismatch)
	}
	
	let bDescriptorType = descriptor_bytes.get_unchecked_value_safe(1);
	if unlikely!(bDescriptorType != descriptor_type)
	{
		return Err(LengthMismatch)
	}
	let remaining_bytes = descriptor_bytes.get_unchecked_range_safe(MinimumUsbDescriptorLength .. );
	Ok(remaining_bytes)
}
