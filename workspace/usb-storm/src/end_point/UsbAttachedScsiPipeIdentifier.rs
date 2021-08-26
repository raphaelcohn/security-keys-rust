// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB Attached SCSI (UAS) Protocol (UASP) pipe.
///
/// For a normal implementation, there should be 4 endpoints, with one of each of Command, Status, DataIn and DataOut.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum UsbAttachedScsiPipeIdentifier
{
	#[allow(missing_docs)]
	Reserved(u8),

	#[allow(missing_docs)]
	Command,
	
	#[allow(missing_docs)]
	Status,
	
	#[allow(missing_docs)]
	DataIn,
	
	#[allow(missing_docs)]
	DataOut,
	
	#[allow(missing_docs)]
	VendorSpecific(u8),
}
