// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[cfg_attr(target_os = "windows", link(name = "winscard"))]
extern "system"
{
	/// * [pcsclite](https://pcsclite.apdu.fr/api/group__API.html#ga4e515829752e0a8dbc4d630696a8d6a5).
	/// * [MSDN](https://msdn.microsoft.com/en-us/library/aa379473.aspx).
	#[cfg_attr(target_os = "windows", link_name = "SCardConnectA")]
	pub(in crate::libpcsc) fn SCardConnect(hContext: SCARDCONTEXT, szReader: *const c_char, dwShareMode: DWORD, dwPreferredProtocols: DWORD, phCard: *mut SCARDHANDLE, pdwActiveProtocol: *mut DWORD) -> LONG;
}
