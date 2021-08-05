// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A reusable buffer.
#[derive(Debug)]
pub struct BinaryObjectStoreBuffer(Vec<MaybeUninit<u8>>);

impl BinaryObjectStoreBuffer
{
	/// Create a new instance.
	#[inline(always)]
	pub fn new() -> Result<Self, TryReserveError>
	{
		Vec::new_buffer(u16::MAX as usize).map(Self)
	}
	
	#[inline(always)]
	fn as_maybe_uninit_slice(&mut self) -> &mut [MaybeUninit<u8>]
	{
		self.0.as_mut_slice()
	}
}
