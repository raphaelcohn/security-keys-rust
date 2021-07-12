// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[cfg_attr(target_os = "windows", link(name = "winscard"))]
extern "system"
{
	/// * [pcsclite](https://pcsclite.apdu.fr/api/group__API.html#gaa1b8970169fd4883a6dc4a8f43f19b67)
	/// * [MSDN](https://msdn.microsoft.com/en-us/library/aa379479.aspx)
	pub(in crate::libpcsc) fn SCardEstablishContext(dwScope: DWORD, pvReserved1: *const c_void, pvReserved2: *const c_void, phContext: *mut SCARDCONTEXT) -> LONG;
}
