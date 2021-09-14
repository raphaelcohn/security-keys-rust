// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Common units.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum CommonUnits<U: Units>
{
	#[allow(missing_docs)]
	None,
	
	#[allow(missing_docs)]
	Defined(U),
	
	#[allow(missing_docs)]
	Reserved,
	
	#[allow(missing_docs)]
	VendorDefined,
}

impl<U: Units> Units for CommonUnits<U>
{
	#[inline(always)]
	fn to_short_format(self) -> &'static str
	{
		use CommonUnits::*;
		
		match self
		{
			None => "none",
			
			Defined(defined) => defined.to_short_format(),
			
			Reserved => "reserved",
			
			VendorDefined => "vendor"
		}
	}
}
