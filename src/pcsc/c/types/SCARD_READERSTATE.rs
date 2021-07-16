// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// * [pcsclite](https://pcsclite.apdu.fr/api/group__API.html#ga33247d5d1257d59e55647c3bb717db24)
/// * [MSDN](https://msdn.microsoft.com/en-us/library/aa379808.aspx)
#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), repr(C))]
#[cfg_attr(any(target_os = "ios", target_os = "macos"), repr(C, packed))]
pub(in crate::pcsc) struct SCARD_READERSTATE
{
	pub(in crate::pcsc) szReader: *const c_char,
	
	pub(in crate::pcsc) pvUserData: *mut c_void,
	
	pub(in crate::pcsc) dwCurrentState: DWORD,
	
	pub(in crate::pcsc) dwEventState: DWORD,
	
	pub(in crate::pcsc) cbAtr: DWORD,
	
	pub(in crate::pcsc) rgbAtr: [u8; ATR_BUFFER_SIZE],
}
