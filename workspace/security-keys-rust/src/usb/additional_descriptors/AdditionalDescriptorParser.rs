// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(in crate::usb) trait AdditionalDescriptorParser
{
	type Descriptor;
	
	type Error: error::Error;
	
	fn no_descriptors_valid() -> bool;
	
	fn multiple_descriptors_valid() -> bool;
	
	/// `bytes` exclude `bLength` and `bDescriptorType` bytes.
	///
	/// `bytes.len()` will always be `<= 253`.
	fn parse_descriptor(&mut self, descriptor_type: DescriptorType, bytes: &[u8]) -> Result<Option<Self::Descriptor>, Self::Error>;
}
