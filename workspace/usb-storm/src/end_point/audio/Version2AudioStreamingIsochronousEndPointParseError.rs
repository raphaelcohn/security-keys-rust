// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2AudioStreamingIsochronousEndPointParseError
{
	#[allow(missing_docs)]
	BLengthTooShort,
	
	#[allow(missing_docs)]
	PitchControlInvalid,
	
	#[allow(missing_docs)]
	DataOverrunControlInvalid,
	
	#[allow(missing_docs)]
	DataUnderrunControlInvalid,
	
	#[allow(missing_docs)]
	InvalidLockDelayUnit
	{
		unit: u8,
	},
}

impl Display for Version2AudioStreamingIsochronousEndPointParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2AudioStreamingIsochronousEndPointParseError
{
}
