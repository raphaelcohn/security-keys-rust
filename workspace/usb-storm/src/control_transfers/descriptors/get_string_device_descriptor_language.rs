// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn get_string_device_descriptor_language(device_handle: NonNull<libusb_device_handle>, buffer: &mut [MaybeUninit<u8>; MaximumStandardUsbDescriptorLength], string_descriptor_index: NonZeroU8, language_identifier: u16) -> Result<DeadOrAlive<Option<&[u8]>>, GetStandardUsbDescriptorError>
{
	get_string_device_descriptor(device_handle, buffer, Some(string_descriptor_index), language_identifier)
}
