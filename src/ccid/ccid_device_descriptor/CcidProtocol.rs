// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(u8)]
pub(crate) enum CcidProtocol
{
	/// Bulk transfer, with optional end point interrupt-IN; only one defined in original specifications,.
	BulkTransfer = 0,
	
	/// ICCD Version A, Control transfers, with no end point interrupt-IN.
	IccdVersionA = 1,
	
	/// ICCD Version B, Control transfers, with optional end point interrupt-IN.
	IccdVersionB = 2,
}
