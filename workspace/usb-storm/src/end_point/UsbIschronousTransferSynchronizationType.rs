// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum UsbIschronousTransferSynchronizationType
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

impl From<SyncType> for UsbIschronousTransferSynchronizationType
{
	#[inline(always)]
	fn from(sync_type: SyncType) -> Self
	{
		match sync_type
		{
			SyncType::NoSync => UsbIschronousTransferSynchronizationType::NoSynchronization,
			
			SyncType::Asynchronous => UsbIschronousTransferSynchronizationType::Asynchronous,
			
			SyncType::Adaptive => UsbIschronousTransferSynchronizationType::Adaptive,
			
			SyncType::Synchronous => UsbIschronousTransferSynchronizationType::Synchronous,
		}
	}
}
