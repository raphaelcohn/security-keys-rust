// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Returns `None` if the `configuration_index` does not have a configuration.
#[inline(always)]
pub(crate) fn get_config_descriptor(libusb_device: NonNull<libusb_device>, configuration_index: u3) -> Result<DeadOrAlive<Option<ConfigurationDescriptor>>, GetConfigurationDescriptorBackendError>
{
	let mut config_descriptor = MaybeUninit::uninit();
	let result = unsafe { libusb_get_config_descriptor(libusb_device.as_ptr(), configuration_index, config_descriptor.as_mut_ptr()) };
	GetConfigurationDescriptorBackendError::parse(result, config_descriptor)
}
