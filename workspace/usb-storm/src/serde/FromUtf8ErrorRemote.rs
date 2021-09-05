// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Deserialize, Serialize)]
#[serde(remote = "FromUtf8Error")]
pub(crate) struct FromUtf8ErrorRemote
{
	#[serde(getter = "FromUtf8ErrorRemote::bytes")] bytes: Vec<u8>,
	
	#[serde(getter = "FromUtf8Error::utf8_error", with = "Utf8ErrorRemote")] error: Utf8Error,
}

impl FromUtf8ErrorRemote
{
	#[inline(always)]
	fn bytes(original: &FromUtf8Error) -> Vec<u8>
	{
		let this = unsafe { & * (original as *const FromUtf8Error as *const Self) };
		this.bytes.clone()
	}
}

impl From<FromUtf8ErrorRemote> for FromUtf8Error
{
	#[inline(always)]
	fn from(remote: FromUtf8ErrorRemote) -> Self
	{
		unsafe{ transmute(remote) }
	}
}
