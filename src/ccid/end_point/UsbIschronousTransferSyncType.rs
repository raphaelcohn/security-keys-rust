// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum UsbIschronousTransferSyncType
{
	/// No synchronisation.
	NoSync,
	
	/// Asynchronous.
	Asynchronous,
	
	/// Adaptive.
	Adaptive,
	
	/// Synchronous.
	Synchronous,
}

impl From<SyncType> for UsbIschronousTransferSyncType
{
	#[inline(always)]
	fn from(sync_type: SyncType) -> Self
	{
		match sync_type
		{
			SyncType::NoSync => UsbIschronousTransferSyncType::NoSync,
			
			SyncType::Asynchronous => UsbIschronousTransferSyncType::Asynchronous,
			
			SyncType::Adaptive => UsbIschronousTransferSyncType::Adaptive,
			
			SyncType::Synchronous => UsbIschronousTransferSyncType::Synchronous,
		}
	}
}
