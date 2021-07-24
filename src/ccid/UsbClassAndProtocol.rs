// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct UsbClassAndProtocol
{
	class_code: u8,
	
	sub_class_code: u8,
	
	protocol_code: u8,
}

impl UsbClassAndProtocol
{
	/// This test is only valid on details held in an Interface Descriptor.
	///
	/// Is this a CCID (Circuit Card Interface Device)?
	#[inline(always)]
	fn is_circuit_card_interface_device(&self, extra_data_length_matches: bool) -> Option<CcidProtocol>
	{
		const CcidClass: u8 = 0x0B;
		const VendorSpecificClass: u8 = 0xFF;
		
		match (self.class_code, self.sub_class_code, self.protocol_code)
		{
			(CcidClass, 0x00, 0x00 ..= 0x02) => self.ccid_protocol(),
			
			// Exists from before standardization.
			(VendorSpecificClass, 0x00, 0x00 ..= 0x02) => if extra_data_length_matches
			{
				self.ccid_protocol()
			}
			else
			{
				None
			},
			
			_ => None,
		}
	}
	
	#[doc(hidden)]
	fn ccid_protocol(&self) -> Option<CcidProtocol>
	{
		Some(unsafe { transmute(self.protocol_code) })
	}
}
