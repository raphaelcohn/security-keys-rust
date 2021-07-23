// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn entry(txt_file_name: &'static str, vendor_name: &'static str, product_name: &'static str, maximum_slot_index: u8, composite_maximum_number_of_slots: Option<NonZeroU8>, protocols: BitFlags<Protocol>, mechanical_features: BitFlags<MechanicalFeature>, features: u32, t1_protocol_maximum_ifsd: usize, maximum_ccid_message_length: usize) -> FixedUsbDeviceCapabilities
{
	FixedUsbDeviceCapabilities::new(txt_file_name, vendor_name, product_name, maximum_slot_index, composite_maximum_number_of_slots, protocols, mechanical_features, Features::parse(features).unwrap(), t1_protocol_maximum_ifsd, maximum_ccid_message_length)
}
