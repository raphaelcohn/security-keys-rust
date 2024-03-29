// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// MPEG Internal Dynamic Range Control.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Mpeg2MultilingualSupport
{
	#[allow(missing_docs)]
	NotSupported,
	
	#[allow(missing_docs)]
	SupportedAtFs,
	
	#[allow(missing_docs)]
	SupportedAtFsAndHalfFs,
}

impl Mpeg2MultilingualSupport
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn is_supported(self) -> bool
	{
		self != Mpeg2MultilingualSupport::NotSupported
	}
	
}
