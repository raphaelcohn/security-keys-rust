// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Physical location.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalLocation
{
	port_number: PortNumber,
	
	port_numbers: ArrayVec<PortNumber, MaximumDevicePortNumbers>,
}

impl PhysicalLocation
{
	#[inline(always)]
	pub(super) fn from_libusb_device(libusb_device: NonNull<libusb_device>) -> Self
	{
		Self
		{
			port_number: get_port_number(libusb_device),
			
			port_numbers: get_port_numbers(libusb_device),
		}
	}
	
	/// Bus number.
	#[inline(always)]
	pub const fn port_number(&self) -> u8
	{
		self.port_number
	}
	
	/// Address address.
	#[inline(always)]
	pub const fn port_numbers(&self) -> &ArrayVec<PortNumber, MaximumDevicePortNumbers>
	{
		&self.port_numbers
	}
}
