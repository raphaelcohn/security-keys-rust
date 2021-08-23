// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn get_standard_interface_descriptor(device_handle: NonNull<libusb_device_handle>, descriptor_type: u8, descriptor_index: u8, interface_number: InterfaceNumber, buffer: &mut [MaybeUninit<u8>]) -> Result<DeadOrAlive<Option<&[u8]>>, GetDescriptorError>
{
	get_interface_descriptor(device_handle, ControlTransferRequestType::Standard, descriptor_type, descriptor_index, interface_number, buffer)
}
