// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


trait EntityDescriptors: Default
{
	type Error: error::Error;
	
	fn parse_entity_body(&mut self, bLength: u8, bDescriptorSubtype: u8, entity_identifier: Option<NonZeroU8>, entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<bool>, EntityDescriptorParseError<Self::Error>>;
}
