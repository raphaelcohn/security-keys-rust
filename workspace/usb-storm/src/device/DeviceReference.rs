// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A pointer abstraction for a libusb concept.
#[derive(Debug)]
#[repr(transparent)]
pub struct DeviceReference(NonNull<libusb_device>);

impl DeviceReference
{
	/// Parse; returns:-
	///
	/// * Ok(Left(device)): Successfully parsed device.
	/// * Ok(Right(location)): Dead device.
	/// * Err(device_reference_parse_error): Device that failed to parse.
	#[inline(always)]
	pub fn parse(&self, reusable_buffer: &mut ReusableBuffer) -> Result<Either<Device, DeadOrFailedToParseDeviceDetails>, DeviceReferenceParseError>
	{
		use DeviceReferenceParseError::*;
		
		let libusb_device = self.0;
		let device_descriptor = get_device_descriptor(libusb_device);
		let vendor_identifier = device_descriptor.idVendor;
		let product_identifier = device_descriptor.idProduct;
		let location = Location::from_libusb_device(libusb_device).map_err(|cause| InvalidLocation { cause, vendor_identifier, product_identifier })?;
		
		let details = DeadOrFailedToParseDeviceDetails
		{
			vendor_identifier,
			
			product_identifier,
			
			location
		};
		match Device::parse(libusb_device, reusable_buffer, details.clone(), device_descriptor)
		{
			Ok(Alive(device)) => Ok(Left(device)),
			
			Ok(Dead) => Ok(Right(details)),
			
			Err(cause) => Err(DeviceParse { cause, details }),
		}
	}
}
