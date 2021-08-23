// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn get_descriptor(device_handle: NonNull<libusb_device_handle>, (request_type, recipient): (ControlTransferRequestType, ControlTransferRecipient), descriptor_type: DescriptorType, descriptor_index: u8, index: u16, buffer: &mut [MaybeUninit<u8>]) -> Result<DeadOrAlive<Option<&[u8]>>, GetDescriptorError>
{
	let value = ((descriptor_type as u16) << 8) | (descriptor_index as u16);
	let result = control_transfer_in(device_handle, (request_type, recipient, Request::GetDescriptor), value, index, buffer);
	GetDescriptorError::parse_result(result)
}
