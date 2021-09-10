// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct MicrosoftUniversallyUniqueIdentifierStringParser<'a>(&'a [u8; UniversallyUniqueIdentifier::MicrosoftStringLength]);

impl<'a> MicrosoftUniversallyUniqueIdentifierStringParser<'a>
{
	#[inline(always)]
	const fn parse(&self) -> [u8; UniversallyUniqueIdentifier::Length]
	{
		self.check_brace::<b'{', 0>();
		self.check_brace::<b'}', 37>();
		
		let pointer = self.0.as_ptr();
		let string = unsafe { & * (pointer.add(1) as *const [u8; UniversallyUniqueIdentifier::Rfc4122StringLength]) };
		UniversallyUniqueIdentifierStringParser(string).parse()
	}
	
	#[inline(always)]
	const fn check_brace<const brace: u8, const index: usize>(&self)
	{
		if self.0[index] == brace
		{
			return
		}
		panic!("Microsoft Universally Unique Identifier (UUID) does not contain a brace where expected")
	}
}
