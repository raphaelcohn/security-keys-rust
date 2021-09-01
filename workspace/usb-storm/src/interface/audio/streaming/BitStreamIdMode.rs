// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Bit stream ID mode.
///
/// When used with AC-3, modes zero to nine inclusive must be set.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[bitflags]
#[serde(deny_unknown_fields)]
#[repr(u32)]
pub enum BitStreamIdMode
{
	#[allow(missing_docs)]
	Zero = 1 << 0,
	
	#[allow(missing_docs)]
	One = 1 << 1,
	
	#[allow(missing_docs)]
	Two = 1 << 2,
	
	#[allow(missing_docs)]
	Three = 1 << 3,
	
	#[allow(missing_docs)]
	Four = 1 << 4,
	
	#[allow(missing_docs)]
	Five = 1 << 5,
	
	#[allow(missing_docs)]
	Six = 1 << 6,
	
	#[allow(missing_docs)]
	Seven = 1 << 7,
	
	#[allow(missing_docs)]
	Eight = 1 << 8,
	
	#[allow(missing_docs)]
	Nine = 1 << 9,
	
	#[allow(missing_docs)]
	Ten = 1 << 10,
	
	#[allow(missing_docs)]
	Eleven = 1 << 11,
	
	#[allow(missing_docs)]
	Twelve = 1 << 12,
	
	#[allow(missing_docs)]
	Thirteen = 1 << 13,
	
	#[allow(missing_docs)]
	Fourteen = 1 << 14,
	
	#[allow(missing_docs)]
	Fifteen = 1 << 15,
	
	#[allow(missing_docs)]
	Sixteen = 1 << 16,
	
	#[allow(missing_docs)]
	Seventeen = 1 << 17,
	
	#[allow(missing_docs)]
	Eightteen = 1 << 18,
	
	#[allow(missing_docs)]
	Nineteen = 1 << 19,
	
	#[allow(missing_docs)]
	Twenty = 1 << 20,
	
	#[allow(missing_docs)]
	TwentyOne = 1 << 21,
	
	#[allow(missing_docs)]
	TwentyTwo = 1 << 22,
	
	#[allow(missing_docs)]
	TwentyThree = 1 << 23,
	
	#[allow(missing_docs)]
	TwentyFour = 1 << 24,
	
	#[allow(missing_docs)]
	TwentyFive = 1 << 25,
	
	#[allow(missing_docs)]
	TwentySix = 1 << 26,
	
	#[allow(missing_docs)]
	TwentySeven = 1 << 27,
	
	#[allow(missing_docs)]
	TwentyEight = 1 << 28,
	
	#[allow(missing_docs)]
	TwentyNine = 1 << 29,
	
	#[allow(missing_docs)]
	Thirty = 1 << 30,
	
	#[allow(missing_docs)]
	ThirtyOne = 1 << 31,
}
