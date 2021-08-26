// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(crate) trait DescriptorParser
{
	type Descriptor;
	
	type Error: error::Error;
	
	/// `remaining_bytes` exclude `bLength` and `bDescriptorType` bytes, but is not sliced to be `bLength` long (`remaining_bytes.len()`); instead, it consists of all remaining bytes after `bDescriptorType`.
	/// The parser must report how many bytes it consumed, which must be at least `bLength`.
	/// This allows the end point parser to consume adjacent descriptors, rather than one at a time.
	///
	/// If the parser returns `None`, then the descriptor is unknown and is handled by the caller of `parse_descrptor()`.
	/// If the parser return `Some(descriptor, consumed_length)`, then it parsed the descriptor (and perhaps an immediately contiguous descriptor in the case of end points), and returns the total length of bytes consumed from `remaining_bytes`. This total length will not include the overhead of the first descriptor's header (`bLength` and `bDescriptorType`).
	///
	/// `remaining_bytes.len()` will always be `<= 253`.
	fn parse_descriptor(&mut self, string_finder: &StringFinder, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>;
	
	#[inline(always)]
	fn unknown(descriptor_type: DescriptorType, bytes: Vec<u8>) -> Self::Descriptor
	{
		unimplemented!("This parser does not support unknown descriptors {} with {:?}", descriptor_type, bytes)
	}
}
