// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn get_descriptor(request_type: ControlTransferRequestType, recipient: ControlTransferRecipient, device_handle: NonNull<libusb_device_handle>, buffer: &mut [MaybeUninit<u8>], descriptor_type: DescriptorType, descriptor_index: u8, index: u16) -> Result<&[u8], ControlTransferError>
{
	const TimeOut: Duration = Duration::from_millis(1_000);
	
	let descriptor_type = (descriptor_type as u16) << 8;
	let value = descriptor_type | (descriptor_index as u16);
	
	control_transfer(Direction::In, request_type, recipient, Request::GetDescriptor, device_handle, TimeOut, value, index, buffer)
}
