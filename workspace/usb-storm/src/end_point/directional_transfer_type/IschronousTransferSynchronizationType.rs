// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Synchronization type.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum IschronousTransferSynchronizationType
{
	/// No synchronisation.
	NoSynchronization,
	
	/// Asynchronous.
	Asynchronous,
	
	/// Adaptive.
	Adaptive,
	
	/// Synchronous.
	Synchronous,
}

impl IschronousTransferSynchronizationType
{
	#[inline(always)]
	fn parse(bmAttributes: u8) -> Self
	{
		use IschronousTransferSynchronizationType::*;
		
		match (bmAttributes & LIBUSB_ISO_SYNC_TYPE_MASK) >> 2
		{
			LIBUSB_ISO_SYNC_TYPE_NONE => NoSynchronization,
			
			LIBUSB_ISO_SYNC_TYPE_ASYNC => Asynchronous,
			
			LIBUSB_ISO_SYNC_TYPE_ADAPTIVE => Adaptive,
			
			LIBUSB_ISO_SYNC_TYPE_SYNC => Synchronous,
			
			_ => unreachable!("Bits have been masked"),
		}
	}
}
