// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[repr(transparent)]
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct ContextInner(SCARDCONTEXT);

impl Drop for ContextInner
{
	#[inline(always)]
	fn drop(&mut self)
	{
		let result = unsafe { SCardReleaseContext(self.0) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			()
		}
		else
		{
			use self::ContextEstablishmentError::*;
			match result
			{
				SCARD_E_NO_SERVICE => (),
				SCARD_F_COMM_ERROR => (),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardReleaseContext()", result),
			}
		}
	}
}
