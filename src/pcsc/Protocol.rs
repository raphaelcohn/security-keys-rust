// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// `#[repr(NonZero(DWORD))]`.
#[cfg_attr(any(target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Protocol
{
	/// ISO/IEC 7186 T=0 protocol.
	T0 = SCARD_PROTOCOL_T0,
	
	/// ISO/IEC 7186 T=1 protocol.
	T1 = SCARD_PROTOCOL_T1,
	
	/// Not defined in Interoperability Specification for ICCs and Personal Computer Systems, Part 5 Version 2.01.01.
	T15 = SCARD_PROTOCOL_T15,
	
	/// Defined in Interoperability Specification for ICCs and Personal Computer Systems, Part 5 Version 2.01.01.
	///
	/// Used for memory-type cards.
	RAW = SCARD_PROTOCOL_RAW,
}

impl Protocol
{
	#[inline(always)]
	const fn into_DWORD(self) -> DWORD
	{
		unsafe { transmute(self) }
	}
	
	#[inline(always)]
	fn get_protocol_pci(self) -> &'static SCARD_IO_REQUEST
	{
		use self::Protocol::*;
		
		match self
		{
			T0 => unsafe { &g_rgSCardT0Pci },
			
			T1 => unsafe { &g_rgSCardT1Pci },
			
			T15 => unimplemented!("No SCARD_IO_REQUEST static global field known"),
			
			RAW => unsafe { &g_rgSCardRawPci },
		}
	}
}
