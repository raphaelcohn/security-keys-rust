// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Localized strings.
///
/// Can contain a maximum of 126 strings (this is an internal limit in USB's design).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedStrings(BTreeMap<Language, String>);

impl Deref for LocalizedStrings
{
	type Target = BTreeMap<Language, String>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl LocalizedStrings
{
	#[inline(always)]
	pub(crate) fn first_value(&self) -> Option<&str>
	{
		self.0.values().next().map(String::as_str)
	}
}
