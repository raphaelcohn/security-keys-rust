// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Maximum length is 33 on macos and with pcsclite and 36 on windows.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct AnswerToReset<'a>(&'a [u8]);

impl<'a> AnswerToReset<'a>
{
	/// Is this valid?
	#[inline(always)]
	pub const fn is_valid(&self) -> bool
	{
		!self.0.is_empty()
	}
}
