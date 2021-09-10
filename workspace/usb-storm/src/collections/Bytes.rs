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
	
	/// From little-endian ordered bytes as used by USB.
	///
	/// This binary format is used by USB.
	///
	/// It has caused substantial confusion (eg <https://github.com/WICG/webusb/issues/115>) not least because the USB 3.1 specification is completely silent on the subject.
	/// WebUSB makes the following observation: the GUID `{3408b638-09a9-47a0-8bfd-a0768815b665}` is sent over the USB bus in the order `0x38, 0xB6, 0x08, 0x34, 0xA9, 0x09, 0xA0, 0x47, 0x8B, 0xFD, 0xA0, 0x76, 0x88, 0x15, 0xB6, 0x65`.
	/// This is the same order produced by the python code `python3 -c "import uuid;print(', '.join(map(hex, uuid.UUID('3408b638-09a9-47a0-8bfd-a0768815b665').bytes_le)))"`.
	/// Note that the GUID 3408b638-09a9-47a0-8bfd-a0768815b665 is RFC 4122 variant (top 3 bits of 8th octet 0xA0 are 0b101).
	fn universally_unique_identifier(&self, index: usize) -> UniversallyUniqueIdentifier;
	
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
	
	fn u32(&self, index: usize) -> u32;
	
	fn u64(&self, index: usize) -> u64;
	
	fn u128(&self, index: usize) -> u128;
	
	fn u8_as_u32(&self, index: usize) -> u32;
	
	fn u16_as_u32(&self, index: usize) -> u32;
	
	fn u8_as_u64(&self, index: usize) -> u64;
	
	fn u16_as_u64(&self, index: usize) -> u64;
	
	fn u24_as_u32(&self, index: usize) -> u24;
	
	fn u24_as_u64(&self, index: usize) -> u64;
	
	fn u32_as_u64(&self, index: usize) -> u64;
	
	fn u40_as_u64(&self, index: usize) -> u40;
	
	fn u48_as_u64(&self, index: usize) -> u48;
	
	fn u56_as_u64(&self, index: usize) -> u56;
}

impl<'a> Bytes for &'a [u8]
{
	#[inline(always)]
	fn bytes(&self, index: usize, length: usize) -> &[u8]
	{
		self.get_unchecked_range_safe(index .. (index + length))
	}
	
	#[inline(always)]
	fn universally_unique_identifier(&self, index: usize) -> UniversallyUniqueIdentifier
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const [u8; 16];
		UniversallyUniqueIdentifier::from_microsoft_mixed_endian_bytes(unsafe { & * offset })
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
	
	#[inline(always)]
	#[cfg(target_endian = "little")]
	fn u128(&self, index: usize) -> u128
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u128;
		unsafe { offset.read_unaligned() }
	}
	
	#[inline(always)]
	#[cfg(target_endian = "big")]
	fn u128(&self, index: usize) -> u128
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u128;
		(unsafe { offset.read_unaligned() }).swap_bytes()
	}
	
	#[inline(always)]
	fn u8_as_u32(&self, index: usize) -> u32
	{
		self.u8(index) as u32
	}
	
	#[inline(always)]
	fn u8_as_u64(&self, index: usize) -> u64
	{
		self.u8(index) as u64
	}
	
	#[inline(always)]
	fn u16_as_u32(&self, index: usize) -> u32
	{
		self.u16(index) as u32
	}
	
	#[inline(always)]
	fn u16_as_u64(&self, index: usize) -> u64
	{
		self.u16(index) as u64
	}
	
	#[inline(always)]
	fn u24_as_u32(&self, index: usize) -> u24
	{
		(self.u8_as_u32(index + 2) << 16) | (self.u8_as_u32(index + 1) << 8) | self.u8_as_u32(index)
	}
	
	#[inline(always)]
	fn u24_as_u64(&self, index: usize) -> u64
	{
		self.u24_as_u32(index) as u64
	}
	
	#[inline(always)]
	fn u32_as_u64(&self, index: usize) -> u64
	{
		self.u32(index) as u64
	}
	
	#[inline(always)]
	fn u40_as_u64(&self, index: usize) -> u40
	{
		(self.u8_as_u64(index + 4) << 32) | (self.u8_as_u64(index + 3) << 24) | (self.u8_as_u64(index + 2) << 16) | (self.u8_as_u64(index + 1) << 8) | self.u8_as_u64(index)
	}
	
	#[inline(always)]
	fn u48_as_u64(&self, index: usize) -> u48
	{
		(self.u8_as_u64(index + 5) << 40) | (self.u8_as_u64(index + 4) << 32) | (self.u8_as_u64(index + 3) << 24) | (self.u8_as_u64(index + 2) << 16) | (self.u8_as_u64(index + 1) << 8) | self.u8_as_u64(index)
	}
	
	#[inline(always)]
	fn u56_as_u64(&self, index: usize) -> u48
	{
		(self.u8_as_u64(index + 6) << 48) | (self.u8_as_u64(index + 5) << 40) | (self.u8_as_u64(index + 4) << 32) | (self.u8_as_u64(index + 3) << 24) | (self.u8_as_u64(index + 2) << 16) | (self.u8_as_u64(index + 1) << 8) | self.u8_as_u64(index)
	}
}
