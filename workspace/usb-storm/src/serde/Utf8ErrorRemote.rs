// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Deserialize, Serialize)]
#[serde(remote = "Utf8Error")]
struct Utf8ErrorRemote
{
	#[serde(getter = "Utf8Error::valid_up_to")] valid_up_to: usize,
	
	#[serde(getter = "Utf8ErrorRemote::error_len")] error_len: Option<u8>,
}

impl Utf8ErrorRemote
{
	#[inline(always)]
	fn error_len(original: &Utf8Error) -> Option<u8>
	{
		let this = unsafe { & * (original as *const Utf8Error as *const Self) };
		this.error_len
	}
}

impl From<Utf8ErrorRemote> for Utf8Error
{
	#[inline(always)]
	fn from(remote: Utf8ErrorRemote) -> Self
	{
		unsafe{ transmute(remote) }
	}
}
