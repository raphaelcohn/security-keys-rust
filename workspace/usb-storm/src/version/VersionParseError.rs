// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB binary coded decimal parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum VersionParseError
{
	#[allow(missing_docs)]
	MajorLeftHandDigitOutOfRange(u8),
	
	#[allow(missing_docs)]
	MajorRightHandDigitOutOfRange(u8),
	
	#[allow(missing_docs)]
	MinorOutOfRange(u8),
	
	#[allow(missing_docs)]
	SubMinorOutOfRange(u8),
}

impl Display for VersionParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for VersionParseError
{
}
