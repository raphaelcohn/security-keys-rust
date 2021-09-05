// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Deserialize, Serialize)]
#[serde(remote = "DecodeUtf16Error")]
pub(crate) struct DecodeUtf16ErrorRemote
{
	#[serde(getter = "DecodeUtf16ErrorRemote::code")] code: u16,
}

impl DecodeUtf16ErrorRemote
{
	#[inline(always)]
	fn code(original: &DecodeUtf16Error) -> u16
	{
		let this = unsafe { & * (original as *const DecodeUtf16Error as *const Self) };
		this.code
	}
}

impl From<DecodeUtf16ErrorRemote> for DecodeUtf16Error
{
	#[inline(always)]
	fn from(remote: DecodeUtf16ErrorRemote) -> Self
	{
		unsafe{ transmute(remote) }
	}
}
