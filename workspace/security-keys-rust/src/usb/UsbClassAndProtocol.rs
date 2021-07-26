// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsbClassAndProtocol
{
	class_code: u8,
	
	sub_class_code: u8,
	
	protocol_code: u8,
}

impl UsbClassAndProtocol
{
	const NoClass: u8 = 0x00;
	const CcidClass: u8 = 0x0B;
	const VendorSpecificClass: u8 = 0xFF;
	
	const NoSubClass: u8 = 0x00;
	const VendorSpecificSubClass: u8 = 0xFF;
	
	const NoProtocol: u8 = 0x00;
	const VendorSpecificProtocol: u8 = 0xFF;
	
	#[inline(always)]
	fn is_device_probable_circuit_card_interface_device(&self) -> bool
	{
		match (self.class_code, self.sub_class_code, self.protocol_code)
		{
			(Self::NoClass, Self::NoSubClass, Self::NoProtocol) => true,
			
			// "Some early Gemalto Ezio CB+ readers have bDeviceClass, bDeviceSubClass and bDeviceProtocol set to 0xFF instead of 0x00".
			(Self::VendorSpecificClass, Self::VendorSpecificSubClass, Self::VendorSpecificProtocol) => true,
			
			_ => false,
		}
	}
	
	/// This test is only valid on details held in an Interface Descriptor.
	///
	/// Is this a CCID (Circuit Card Interface Device)?
	#[inline(always)]
	fn is_interface_circuit_card_interface_device(&self, extra_data_length_matches: bool) -> Option<CcidProtocol>
	{
		match (self.class_code, self.sub_class_code, self.protocol_code)
		{
			(Self::CcidClass, 0x00, 0x00 ..= 0x02) => self.ccid_protocol(),
			
			// Exists from before standardization.
			(Self::VendorSpecificClass, 0x00, 0x00 ..= 0x02) => if extra_data_length_matches
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
