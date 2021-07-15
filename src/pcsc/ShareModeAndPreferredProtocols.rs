// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum ShareModeAndPreferredProtocols
{
	Direct,

	Exclusive(PreferredProtocols),

	Shared(PreferredProtocols),
}

impl ShareModeAndPreferredProtocols
{
	pub(crate) const ExclusiveAnyProtocol: Self = Self::Exclusive(PreferredProtocols::T0_or_T1);
	
	pub(crate) const SharedAnyProtocol: Self = Self::Shared(PreferredProtocols::T0_or_T1);
	
	#[inline(always)]
	fn into_DWORDs(self) -> (DWORD, DWORD, bool, bool)
	{
		use self::ShareModeAndPreferredProtocols::*;
		
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
