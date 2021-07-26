// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsbClassAndProtocol<DOI: DeviceOrInterface>
{
	class_code: u8,
	
	sub_class_code: u8,
	
	protocol_code: u8,

	marker: PhantomData<DOI>,
}

impl<DOI: DeviceOrInterface> UsbClassAndProtocol<DOI>
{
	#[inline(always)]
	pub(super) fn new(class_code: u8, sub_class_code: u8, protocol_code: u8) -> Self
	{
		Self
		{
			class_code,
		
			sub_class_code,
		
			protocol_code,
			
			marker: PhantomData,
		}
	}
}

impl UsbClassAndProtocol<Device>
{
	#[inline(always)]
	pub(super) fn is_device_probable_circuit_card_interface_device(&self) -> bool
	{
		match (self.class_code, self.sub_class_code, self.protocol_code)
		{
			(Device::UseClassInformationInTheInterfaceDescriptorsClass, Device::UseClassInformationInTheInterfaceDescriptorsSubClass, Device::UseClassInformationInTheInterfaceDescriptorsProtocol) => true,
			
			// "Some early Gemalto Ezio CB+ readers have bDeviceClass, bDeviceSubClass and bDeviceProtocol set to 0xFF instead of 0x00".
			(Device::VendorSpecificClass, Device::VendorSpecificSubClass, Device::VendorSpecificProtocol) => true,
			
			_ => false,
		}
	}
}

impl UsbClassAndProtocol<Interface>
{
	/// This test is only valid on details held in an Interface Descriptor.
	///
	/// Is this a CCID (Circuit Card Interface Device)?
	#[inline(always)]
	pub(super) fn is_interface_circuit_card_interface_device(&self, extra_data_length_matches: bool) -> Option<CcidProtocol>
	{
		match (self.class_code, self.sub_class_code, self.protocol_code)
		{
			(Interface::SmartCardClass, 0x00, 0x00 ..= 0x02) => self.ccid_protocol(),
			
			// Exists from before standardization.
			(Interface::VendorSpecificClass, 0x00, 0x00 ..= 0x02) => if extra_data_length_matches
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
