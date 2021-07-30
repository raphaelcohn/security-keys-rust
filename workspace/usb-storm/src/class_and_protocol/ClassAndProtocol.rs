// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClassAndProtocol<DOI: DeviceOrAlternateSetting>
{
	class_code: u8,
	
	sub_class_code: u8,
	
	protocol_code: u8,

	#[serde(skip)] marker: PhantomData<DOI>,
}

impl<DOI: DeviceOrAlternateSetting> ClassAndProtocol<DOI>
{
	/// Communications and Communications Device Class (CDC) Control.
	///
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass02h>.
	const CommunicationsAndCommunicationsDeviceClassControlClass: u8 = 0x02;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassDCh>.
	const DiagnosticDeviceClass: u8 = 0xDC;
	
	/// See https://www.usb.org/defined-class-codes#anchor_BaseClassEFh.
	const MiscellaneousClass: u8 = 0xEF;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassFFh>.
	pub(crate) const VendorSpecificClass: u8 = 0xFF;
	pub(crate) const VendorSpecificSubClass: u8 = 0xFF;
	pub(crate) const VendorSpecificProtocol: u8 = 0xFF;
	
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

impl ClassAndProtocol<Device>
{
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass00h>.
	const UseClassInformationInTheInterfaceDescriptorsClass: u8 = 0x00;
	const UseClassInformationInTheInterfaceDescriptorsSubClass: u8 = 0x00;
	const UseClassInformationInTheInterfaceDescriptorsProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass09h>.
	const HubClass: u8 = 0x09;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass11h>.
	const BillboardDeviceClass: u8 = 0x12;
	
	const BillboardDeviceSubClass: u8 = 0x00;
	
	const BillboardDeviceProtocol: u8 = 0x00;
	
	#[inline(always)]
	pub(super) fn new_from_device(device_descriptor: &libusb_device_descriptor) -> Self
	{
		Self::new
		(
			device_descriptor.bDeviceClass,
			
			device_descriptor.bDeviceSubClass,
			
			device_descriptor.bDeviceProtocol,
		)
	}
	
	#[inline(always)]
	pub(super) fn is_valid_smart_card_device(&self) -> bool
	{
		match (self.class_code, self.sub_class_code, self.protocol_code)
		{
			(Self::UseClassInformationInTheInterfaceDescriptorsClass, Self::UseClassInformationInTheInterfaceDescriptorsSubClass, Self::UseClassInformationInTheInterfaceDescriptorsProtocol) => true,
			
			// "Some early Gemalto Ezio CB+ readers (2011) have bDeviceClass, bDeviceSubClass and bDeviceProtocol set to 0xFF instead of 0x00".
			(Self::VendorSpecificClass, Self::VendorSpecificSubClass, Self::VendorSpecificProtocol) => true,
			
			_ => false,
		}
	}
}

impl ClassAndProtocol<AlternateSetting>
{
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass01h>.
	const AudioClass: u8 = 0x01;
	
	/// Human Interface Device (HID).
	///
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass03h>.
	pub(crate) const HumanInterfaceDeviceClass: u8 = 0x03;
	
	/// See Device Class Definition for Human Interface Devices (HID) Version 1.11, Section 4.2 Subclass.
	pub(crate) const HumanInterfaceDeviceNoSubClass: u8 = 0x00;
	pub(crate) const HumanInterfaceDeviceBootInterfaceSubClass: u8 = 0x01;
	pub(crate) const HumanInterfaceDeviceBootInterfaceNoneProtocol: u8 = 0x00;
	pub(crate) const HumanInterfaceDeviceBootInterfaceKeyboardProtocol: u8 = 0x01;
	pub(crate) const HumanInterfaceDeviceBootInterfaceMouseProtocol: u8 = 0x02;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass05h>.
	const PhysicalClass: u8 = 0x05;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass06h>.
	const StillImagingClass: u8 = 0x06;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass07h>.
	const PrinterClass: u8 = 0x07;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass08h>.
	const MassStorageClass: u8 = 0x08;
	const MassStorageSubClass: u8 = 0x00;
	const MassStorageFullSpeedHubProtocol: u8 = 0x00;
	const MassStorageHiSpeedHubWithSingleTTProtocol: u8 = 0x01;
	const MassStorageHiSpeedHubWithMultipleTTsProtocol: u8 = 0x02;
	
	/// Communications Device Class (CDC) Data.
	///
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Ah>.
	const CommunicationsDeviceClassDataClass: u8 = 0x0A;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Bh>.
	pub(crate) const SmartCardClass: u8 = 0x0B;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Dh>.
	const ContentSecurityClass: u8 = 0x0D;
	const ContentSecuritySubClass: u8 = 0x00;
	const ContentSecurityProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Eh>.
	const VideoClass: u8 = 0x0E;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Fh>.
	const PersonalHealthcareClass: u8 = 0x0F;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass10h>.
	const AudioVideoDevicesClass: u8 = 0x10;
	const AudioVideoControlSubClass: u8 = 0x01;
	const AudioVideoControlSubClassProtocol: u8 = 0x00;
	const AudioVideoVideoStreamingSubClass: u8 = 0x02;
	const AudioVideoVideoStreamingSubClassProtocol: u8 = 0x00;
	const AudioVideoAudioStreamingSubClass: u8 = 0x03;
	const AudioVideoAudioStreamingSubClassProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass12h>.
	const UsbTypeCBridgeClass: u8 = 0x12;
	const UsbTypeCBridgeSubClass: u8 = 0x00;
	const UsbTypeCBridgeProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassE0h>.
	const WirelessControllerClass: u8 = 0xE0;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassFEh>.
	const ApplicationSpecificClass: u8 = 0xFE;
	
	#[inline(always)]
	pub(crate) fn new_from_alternate_setting(alternate_setting: &libusb_interface_descriptor) -> Self
	{
		Self::new
		(
			alternate_setting.bInterfaceClass,
			
			alternate_setting.bInterfaceSubClass,
			
			alternate_setting.bInterfaceProtocol,
		)
	}
}
