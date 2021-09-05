// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Deserialize, Serialize)]
#[serde(remote = "Layout")]
struct LayoutRemote
{
	#[serde(getter = "Layout::size")] size_: usize,
	
	#[serde(getter = "LayoutRemote::align")] align_: NonZeroUsize,
}

impl LayoutRemote
{
	#[inline(always)]
	fn align(original: &Layout) -> NonZeroUsize
	{
		new_non_zero_usize(original.align())
	}
}

impl From<LayoutRemote> for Layout
{
	#[inline(always)]
	fn from(remote: LayoutRemote) -> Self
	{
		unsafe{ transmute(remote) }
	}
}
