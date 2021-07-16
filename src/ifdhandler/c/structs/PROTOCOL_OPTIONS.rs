// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub(in crate::ifdhandler) struct PROTOCOL_OPTIONS
{
	/// Tag 0x0201.
	pub(in crate::ifdhandler) Protocol_Type: DWORD,
	
	/// Tag 0x0202.
	pub(in crate::ifdhandler) Current_Clock: DWORD,
	
	/// Tag 0x0203.
	pub(in crate::ifdhandler) Current_F: DWORD,
	
	/// Tag 0x0204.
	pub(in crate::ifdhandler) Current_D: DWORD,
	
	/// Tag 0x0205.
	pub(in crate::ifdhandler) Current_N: DWORD,
	
	/// Tag 0x0206.
	pub(in crate::ifdhandler) Current_W: DWORD,
	
	/// Tag 0x0207.
	pub(in crate::ifdhandler) Current_IFSC: DWORD,
	
	/// Tag 0x0208.
	pub(in crate::ifdhandler) Current_IFSD: DWORD,
	
	/// Tag 0x0209.
	pub(in crate::ifdhandler) Current_BWT: DWORD,
	
	/// Tag 0x020A.
	pub(in crate::ifdhandler) Current_CWT: DWORD,
	
	/// Tag 0x020B.
	pub(in crate::ifdhandler) Current_EBC: DWORD,
}
