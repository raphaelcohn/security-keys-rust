// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[cfg_attr(target_os = "windows", link(name = "winscard"))]
extern "system"
{
	#[cfg_attr(target_os = "windows", link_name = "SCardStatusA")]
	pub(in crate::pcsc) fn SCardStatus(hCard: SCARDHANDLE, szReaderName: *mut c_char, pcchReaderLen: *mut DWORD, pdwState: *mut DWORD, pdwProtocol: *mut DWORD, pbAtr: *mut u8, pcbAtrLen: *mut DWORD) -> LONG;
}
