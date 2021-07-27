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
	
	#[inline(always)]
	pub(super) fn codes(self) -> (u8, u8, u8)
	{
		(self.class_code, self.sub_class_code, self.protocol_code)
	}
}

impl UsbClassAndProtocol<Device>
{
	#[inline(always)]
	pub(crate) fn new_from_device(device_descriptor: &DeviceDescriptor) -> Self
	{
		Self::new
		(
			device_descriptor.class_code(),
			
			device_descriptor.sub_class_code(),
			
			device_descriptor.protocol_code(),
		)
	}
	
	#[inline(always)]
	pub(super) fn is_valid_smart_card_device(&self) -> bool
	{
		match (self.class_code, self.sub_class_code, self.protocol_code)
		{
			(Device::UseClassInformationInTheInterfaceDescriptorsClass, Device::UseClassInformationInTheInterfaceDescriptorsSubClass, Device::UseClassInformationInTheInterfaceDescriptorsProtocol) => true,
			
			// "Some early Gemalto Ezio CB+ readers (2011) have bDeviceClass, bDeviceSubClass and bDeviceProtocol set to 0xFF instead of 0x00".
			(Device::VendorSpecificClass, Device::VendorSpecificSubClass, Device::VendorSpecificProtocol) => true,
			
			_ => false,
		}
	}
}

impl UsbClassAndProtocol<Interface>
{
	#[inline(always)]
	pub(crate) fn new_from_interface(interface_descriptor: &InterfaceDescriptor) -> Self
	{
		Self::new
		(
			interface_descriptor.class_code(),
			
			interface_descriptor.sub_class_code(),
			
			interface_descriptor.protocol_code(),
		)
	}
}
