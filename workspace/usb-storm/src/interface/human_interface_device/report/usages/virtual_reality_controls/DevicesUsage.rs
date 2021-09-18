// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Virtual reality controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum DevicesUsage
{
	#[allow(missing_docs)]
	Belt,
	
	#[allow(missing_docs)]
	BodySuit,
	
	#[allow(missing_docs)]
	Flexor,
	
	#[allow(missing_docs)]
	Glove,
	
	#[allow(missing_docs)]
	HeadTracker,
	
	#[allow(missing_docs)]
	HeadMountedDisplay,
	
	#[allow(missing_docs)]
	HandTracker,
	
	#[allow(missing_docs)]
	Oculometer,
	
	#[allow(missing_docs)]
	Vest,
	
	#[allow(missing_docs)]
	AnimatronicDevice,
}
