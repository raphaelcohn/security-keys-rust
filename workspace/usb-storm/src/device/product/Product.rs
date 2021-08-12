// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A product.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Product
{
	identifier: ProductIdentifier,
	
	name: Option<LocalizedStrings>,
}

impl Product
{
	#[inline(always)]
	pub(super) const fn new(identifier: ProductIdentifier, name: Option<LocalizedStrings>) -> Self
	{
		Self
		{
			identifier,
		
			name,
		}
	}
	
	/// Identifier.
	#[inline(always)]
	pub const fn identifier(&self) -> ProductIdentifier
	{
		self.identifier
	}
	
	/// Name(s).
	#[inline(always)]
	pub fn name(&self) -> Option<&LocalizedStrings>
	{
		self.name.as_ref()
	}
}
