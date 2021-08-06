// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(crate) trait AdditionalDescriptorParser
{
	type Descriptor;
	
	type Error: error::Error;
	
	fn no_descriptors_valid() -> bool;
	
	fn multiple_descriptors_valid() -> bool;
	
	/// `remaining_bytes` exclude `bLength` and `bDescriptorType` bytes, but is not sliced to be `bLength` long (`remaining_bytes.len()`); instead, it consists of all remaining bytes.
	/// The parser must report how many bytes it consumed, which must be at least `bLength`.
	/// This allows the end point parser to consume adjacent descriptors, rather than one at a time.
	///
	/// `remaining_bytes.len()` will always be `<= 253`.
	fn parse_descriptor(&mut self, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<(Self::Descriptor, usize)>, Self::Error>;
}
