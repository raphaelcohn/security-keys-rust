// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Mass storage sub class.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum MassStorageProtocol
{
	/// Control/Bulk/Interrupt (CBI) transport.
	///
	/// Obsolescent.
	ControlBulkInterruptTransportWithCommandCompletionInterrupt,
	
	/// Control/Bulk/Interrupt (CBI) transport.
	///
	/// Obsolescent.
	ControlBulkInterruptTransportWithoutCommandCompletionInterrupt,

	#[allow(missing_docs)]
	Obsolete,
	
	#[allow(missing_docs)]
	VendorSpecific,

	/// Bulk-Only Transport (BBB).
	BulkOnly,
	
	/// USB Attached SCSI (UAS) Protocol (UASP) (see <https://www.t10.org/drafts.htm#SCSI3_UAS> and look for 'D2095').
	UsbAttachedScsi,
	
	#[allow(missing_docs)]
	Unrecognized(u8),
}
