// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum UsbDirection
{
	/// Direction for read (device to host) transfers.
	In,
	
	/// Direction for write (host to device) transfers.
	Out,
}

impl From<Direction> for UsbDirection
{
	#[inline(always)]
	fn from(direction: Direction) -> Self
	{
		match direction
		{
			Direction::In => UsbDirection::In,
			
			Direction::Out => UsbDirection::Out,
		}
	}
}
