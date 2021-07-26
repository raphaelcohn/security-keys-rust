// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[cfg_attr(target_os = "windows", link(name = "winscard"))]
extern "system"
{
	pub(in crate::pcsc) fn SCardControl(hCard: SCARDHANDLE, dwControlCode: DWORD, pbSendBuffer: *const u8, cbSendLength: DWORD, pbRecvBuffer: *mut u8, cbRecvLength: DWORD, lpBytesReturned: *mut DWORD) -> LONG;
}
