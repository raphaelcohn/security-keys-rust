// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum InternalExceptionError
{
	/// Not supported or invalid.
	NoInformationGiven,
 
	/// `value` is ?
	NoPreciseDiagnosis
	{
		/// Will not be 0xFF.
		/// Range between `0x01 ..= 0xFE`.
		value: NonZeroU8,
	},
	
	/// eg due to overuse.
	CardDead,
}

impl InternalExceptionError
{
	#[inline(always)]
	fn categorize_response_code(sw2: u8) -> Self
	{
		use self::InternalExceptionError::*;
		
		match sw2
		{
			0x00 => NoInformationGiven,
			
			0x01 ..= 0xFE => NoPreciseDiagnosis
			{
				value: unsafe { NonZeroU8::new_unchecked(sw2) },
			},
			
			0xFF => CardDead,
		}
	}
}
