// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Maximum streams.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub struct BulkMaximumStreamsExponent(pub(super) NonZeroU8);

impl BulkMaximumStreamsExponent
{
	/// Always a power-of-two up to 65,536 inclusive.
	#[inline(always)]
	pub const fn number_of_streams_supported(self) -> NonZeroU32
	{
		new_non_zero_u32(1 << self.0.get())
	}
}
