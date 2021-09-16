// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DelimitedLocalItemParseError
{
	#[allow(missing_docs)]
	Designator,
	
	#[allow(missing_docs)]
	DesignatorMinimum,
	
	#[allow(missing_docs)]
	DesignatorMaximum,
	
	#[allow(missing_docs)]
	String,
	
	#[allow(missing_docs)]
	StringMinimum,
	
	#[allow(missing_docs)]
	StringMaximum,
	
	#[allow(missing_docs)]
	Reserved(ReservedLocalItemTag),
	
	#[allow(missing_docs)]
	Long,
}

impl Display for DelimitedLocalItemParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for DelimitedLocalItemParseError
{
}
