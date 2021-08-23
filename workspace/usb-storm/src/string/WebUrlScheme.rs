// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A Web URL scheme prefix.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum WebUrlScheme
{
	/// URL implicitly starts with 'http://'.
	HTTP,
	
	/// URL implicitly starts with 'https://'.
	HTTPS,
	
	#[allow(missing_docs)]
	Unrecognized
	{
		scheme: u8,
	},
	
	/// URL has scheme at its start.
	Empty,
}

impl WebUrlScheme
{
	#[inline(always)]
	fn parse(descriptor_bytes: &[u8]) -> WebUrlScheme
	{
		use WebUrlScheme::*;
		match descriptor_bytes.u8(0)
		{
			0 => HTTP,
			
			1 => HTTPS,
			
			scheme @ 2 ..= 254 => Unrecognized { scheme },
			
			255 => Empty,
		}
	}
}
