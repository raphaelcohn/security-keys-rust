// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn get_human_interface_device_report_interface_descriptor(device_handle: NonNull<libusb_device_handle>, buffer: &mut [MaybeUninit<u8>], interface_number: InterfaceNumber) -> Result<&[u8], ControlTransferError>
{
	get_standard_interface_descriptor(device_handle, buffer, LIBUSB_DT_REPORT, 0, interface_number)
}
