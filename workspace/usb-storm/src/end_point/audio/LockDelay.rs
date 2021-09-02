// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// "Indicates the time it takes this endpoint to reliably lock its internal clock recovery circuitry".
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
pub enum LockDelay
{
	#[allow(missing_docs)]
	Undefined(u16),
	
	#[allow(missing_docs)]
	Milliseconds(u16),

	#[allow(missing_docs)]
	DecodedPcmSamples(u16),
}

impl LockDelay
{
	#[inline(always)]
	fn parse<E: error::Error>(unit: u8, delay: u16, error: E) -> Result<Self, E>
	{
		use LockDelay::*;
		
		let ok = match unit
		{
			0 => Undefined(delay),
			
			1 => Milliseconds(delay),
			
			2 => DecodedPcmSamples(delay),
			
			_ => return Err(error)
		};
		Ok(ok)
	}
}
