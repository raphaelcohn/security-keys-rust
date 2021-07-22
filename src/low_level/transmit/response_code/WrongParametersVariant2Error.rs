// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Covers Parameters P1 and P2.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum WrongParametersVariant2Error
{
	NoInformationGiven,

	/// As per ISO 7816-3.
	ReferenceIncorrect
	{
		value: NonZeroU8,
	}
}

impl WrongParametersVariant2Error
{
	#[inline(always)]
	fn categorize_response_code(sw2: u8) -> Self
	{
		use self::WrongParametersVariant2Error::*;
		
		match sw2
		{
			0x00 => NoInformationGiven,
			
			_ => ReferenceIncorrect
			{
				value: unsafe { NonZeroU8::new_unchecked(sw2) },
			},
		}
	}
}
