// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A logical audio channel spatial location.
pub trait LogicalAudioChannelSpatialLocation: Debug + Copy + Eq + Ord + Hash + BitFlag
{
	#[doc(hidden)]
	fn parse_mode_bit_map(process_type_specific_bytes: &[u8], index: usize) -> Self::Numeric;
}
