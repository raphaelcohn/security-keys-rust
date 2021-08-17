// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Logical location.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalLocation
{
	bus_number: u8,

	assigned_address: AssignedAddress,
}

impl LogicalLocation
{
	#[inline(always)]
	pub(super) fn from_libusb_device(libusb_device: NonNull<libusb_device>) -> Result<Self, ()>
	{
		Ok
		(
			Self
			{
				bus_number: get_bus_number(libusb_device),
				
				assigned_address:
				{
					let address = get_device_address(libusb_device);
					if unlikely!(address == 0)
					{
						return Err(())
					}
					new_non_zero_u8(address)
				}
			}
		)
	}
	
	/// Bus number.
	#[inline(always)]
	pub const fn bus_number(self) -> u8
	{
		self.bus_number
	}
	
	/// Address address.
	#[inline(always)]
	pub const fn assigned_address(self) -> AssignedAddress
	{
		self.assigned_address
	}
}
