// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(crate) trait Bytes
{
	fn bytes(&self, index: usize, length: usize) -> &[u8];
	
	#[inline(always)]
	fn version(&self, index: usize) -> Result<Version, VersionParseError>
	{
		Version::parse(self.u16(index))
	}
	
	fn uuid(&self, index: usize) -> Uuid;
	
	#[inline(always)]
	fn optional_non_zero_u8(&self, index: usize) -> Option<NonZeroU8>
	{
		unsafe { transmute(self.u8(index)) }
	}
	
	#[inline(always)]
	fn optional_non_zero_u16(&self, index: usize) -> Option<NonZeroU16>
	{
		unsafe { transmute(self.u16(index)) }
	}
	
	fn u8(&self, index: usize) -> u8;
	
	fn u16(&self, index: usize) -> u16;
	
	fn u24(&self, index: usize) -> u24;
	
	fn u32(&self, index: usize) -> u32;
	
	fn u64(&self, index: usize) -> u64;
}

impl<'a> Bytes for &'a [u8]
{
	#[inline(always)]
	fn bytes(&self, index: usize, length: usize) -> &[u8]
	{
		self.get_unchecked_range_safe(index .. (index + length))
	}
	
	#[inline(always)]
	fn uuid(&self, index: usize) -> Uuid
	{
		let pointer = self.as_ptr() as *const u128;
		let bytes = unsafe { pointer.add(index).read_volatile() };
		Uuid::from_bytes(bytes.to_be_bytes())
	}
	
	#[inline(always)]
	fn u8(&self, index: usize) -> u8
	{
		self.get_unchecked_value_safe(index)
	}
	
	#[inline(always)]
	#[cfg(target_endian = "little")]
	fn u16(&self, index: usize) -> u16
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u16;
		unsafe { offset.read_unaligned() }
	}
	
	#[inline(always)]
	#[cfg(target_endian = "big")]
	fn u16(&self, index: usize) -> u16
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u16;
		(unsafe { offset.read_unaligned() }).swap_bytes()
	}
	
	#[inline(always)]
	fn u24(&self, index: usize) -> u24
	{
		u32::from_le_bytes([0x00, self.get_unchecked_value_safe(index), self.get_unchecked_value_safe(index + 1), self.get_unchecked_value_safe(index + 2)])
	}
	
	#[inline(always)]
	#[cfg(target_endian = "little")]
	fn u32(&self, index: usize) -> u32
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u32;
		unsafe { offset.read_unaligned() }
	}
	
	#[inline(always)]
	#[cfg(target_endian = "big")]
	fn u32(&self, index: usize) -> u32
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u32;
		(unsafe { offset.read_unaligned() }).swap_bytes()
	}
	
	#[inline(always)]
	#[cfg(target_endian = "little")]
	fn u64(&self, index: usize) -> u64
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u64;
		unsafe { offset.read_unaligned() }
	}
	
	#[inline(always)]
	#[cfg(target_endian = "big")]
	fn u64(&self, index: usize) -> u64
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u64;
		(unsafe { offset.read_unaligned() }).swap_bytes()
	}
}
