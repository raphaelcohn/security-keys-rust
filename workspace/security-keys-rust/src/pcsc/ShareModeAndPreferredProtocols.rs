// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// How to share the card and which protocols to use with it if shared or exclusive.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum ShareModeAndPreferredProtocols
{
	/// Direct, protocol-less access.
	///
	/// This mode does not support transmitting Application Protocol Data Units (APDUs), only control codes.
	///
	/// Note that on Windows this gives exclusive access; on macos and Linux shared access!
	Direct,

	/// Exclusive access desired; the card must not be shared with anyone else.
	Exclusive(PreferredProtocols),
	
	/// Shared access; other processes and threads can access the card, but transactions can be used to prevent this as needed.
	Shared(PreferredProtocols),
}

impl ShareModeAndPreferredProtocols
{
	/// Exclusive, any of `T=0` or `T=1` protocols.
	pub const ExclusiveAnyProtocol: Self = Self::Exclusive(PreferredProtocols::T0_or_T1);
	
	/// Shared, any of `T=0` or `T=1` protocols.
	pub const SharedAnyProtocol: Self = Self::Shared(PreferredProtocols::T0_or_T1);
	
	#[inline(always)]
	fn into_DWORDs(self) -> (DWORD, DWORD, bool, bool)
	{
		use ShareModeAndPreferredProtocols::*;
		
		#[cfg(not(target_os = "windows"))] const IsDirectModeShared: bool = false;
		#[cfg(target_os = "windows")] const IsDirectModeShared: bool = true;
		
		match self
		{
			Direct => (SCARD_SHARE_DIRECT, 0, true, IsDirectModeShared),
			
			Exclusive(preferred_protocols) => (SCARD_SHARE_EXCLUSIVE, preferred_protocols.into_DWORD(), false, false),
			
			Shared(preferred_protocols) => (SCARD_SHARE_SHARED, preferred_protocols.into_DWORD(), false, true),
		}
	}
}
