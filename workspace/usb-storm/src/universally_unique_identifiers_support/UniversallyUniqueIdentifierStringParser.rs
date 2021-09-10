// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct UniversallyUniqueIdentifierStringParser<'a>(&'a [u8; UniversallyUniqueIdentifier::Rfc4122StringLength]);

impl<'a> UniversallyUniqueIdentifierStringParser<'a>
{
	#[inline(always)]
	const fn parse(&self) -> [u8; UniversallyUniqueIdentifier::Length]
	{
		self.check_hyphens();
		
		[
			// time_low
			self.extract_byte::<0>(),
			self.extract_byte::<2>(),
			self.extract_byte::<4>(),
			self.extract_byte::<6>(),
			
			// time_mid
			self.extract_byte::<9>(),
			self.extract_byte::<11>(),
			
			// time_high_and_version
			self.extract_byte::<14>(),
			self.extract_byte::<16>(),
			
			// clock_sequence
			self.extract_byte::<19>(),
			self.extract_byte::<21>(),
			
			// node
			self.extract_byte::<24>(),
			self.extract_byte::<26>(),
			self.extract_byte::<28>(),
			self.extract_byte::<30>(),
			self.extract_byte::<32>(),
			self.extract_byte::<34>(),
		]
	}
	
	#[inline(always)]
	const fn check_hyphens(&self)
	{
		self.check_hyphen::<8>();
		self.check_hyphen::<13>();
		self.check_hyphen::<18>();
		self.check_hyphen::<23>();
	}
	
	#[inline(always)]
	const fn check_hyphen<const index: usize>(&self)
	{
		let hyphen = self.0[index];
		if hyphen == b'-'
		{
			return
		}
		panic!("Universally Unique Identifier (UUID) does not contain a hyphen where expected")
	}
	
	#[inline(always)]
	const fn extract_byte<const index: usize>(&self) -> u8
	{
		let upper_nibble = self.extract_nibble(index);
		let lower_nibble = self.extract_nibble(index + 1);
		
		(upper_nibble << 4) | lower_nibble
	}
	
	#[inline(always)]
	const fn extract_nibble(&self, index: usize) -> u8
	{
		let nibble = self.0[index];
		
		let subtract = match nibble
		{
			b'0' ..= b'9' => UniversallyUniqueIdentifier::DecimalOffset,
			
			b'A' ..= b'F' => UniversallyUniqueIdentifier::UpperCaseHexadecimalOffset,
			
			b'a' ..= b'f' => UniversallyUniqueIdentifier::LowerCaseHexadecimalOffset,
			
			_ => panic!("UUID has invalid nibble"),
		};
		nibble - subtract
	}
}
