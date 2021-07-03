// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(crate) struct SendBuffer(Vec<u8>);

impl SendBuffer
{
	#[allow(deprecated)]
	#[inline(always)]
	pub(super) fn allocate() -> Result<Self, TryReserveError>
	{
		const FixedHeaderSize: usize = 4;
		
		const MaximumLcSize: usize = 3;
		
		const MaximumDataLength: usize = 65_535;
		
		const MaximumLeSize: usize = 3;
		
		Ok(Self(Vec::new_with_capacity(FixedHeaderSize + MaximumLcSize + MaximumDataLength + MaximumLeSize)?))
	}
	
	#[inline(always)]
	fn reserve_send(&mut self) -> &mut Vec<u8>
	{
		self.0.clear();
		&mut self.0
	}
}
