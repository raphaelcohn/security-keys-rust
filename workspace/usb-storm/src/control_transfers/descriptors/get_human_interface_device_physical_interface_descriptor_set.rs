// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[allow(dead_code)]
#[inline(always)]
pub(crate) fn get_human_interface_device_physical_interface_descriptor_set(device_handle: NonNull<libusb_device_handle>, buffer: &mut [MaybeUninit<u8>], set_number: NonZeroU8, interface_number: InterfaceNumber) -> Result<&[u8], ControlTransferError>
{
	get_human_interface_device_physical_interface_descriptor(device_handle, buffer, Some(set_number), interface_number)
}
