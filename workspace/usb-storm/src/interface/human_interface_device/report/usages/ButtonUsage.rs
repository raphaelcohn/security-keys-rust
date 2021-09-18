// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Button usage.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ButtonUsage
{
	#[allow(missing_docs)]
	NoButtonPressed,

	/// Increasing ordinals have less significance.
	Ordinal(NonZeroU16)
}

impl Default for ButtonUsage
{
	#[inline(always)]
	fn default() -> Self
	{
		ButtonUsage::NoButtonPressed
	}
}

impl From<UsageIdentifier> for ButtonUsage
{
	#[inline(always)]
	fn from(identifier: UsageIdentifier) -> Self
	{
		unsafe { transmute(identifier) }
	}
}
