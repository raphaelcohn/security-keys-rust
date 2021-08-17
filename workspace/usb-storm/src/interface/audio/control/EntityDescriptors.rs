// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


trait EntityDescriptors: Default
{
	type Error: error::Error;
	
	fn parse_entity_body(&mut self, bDescriptorSubtype: u8, string_finder: &StringFinder, entity_descriptors_bytes: &[u8], bLength: u8) -> Result<DeadOrAlive<bool>, EntityDescriptorParseError<Self::Error>>;
}
