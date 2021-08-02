// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassAndProtocol<DOI: DeviceOrAlternateSetting>
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
	#[allow(dead_code)]
	const CommunicationsAndCommunicationsDeviceClassControlClass: u8 = 0x02;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassDCh>.
	#[allow(dead_code)]
	const DiagnosticDeviceClass: u8 = 0xDC;
	
	/// See https://www.usb.org/defined-class-codes#anchor_BaseClassEFh.
	#[allow(dead_code)]
	const MiscellaneousClass: u8 = 0xEF;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassFFh>.
	pub(crate) const VendorSpecificClass: u8 = 0xFF;
	#[allow(dead_code)]
	const VendorSpecificSubClass: u8 = 0xFF;
	#[allow(dead_code)]
	const VendorSpecificProtocol: u8 = 0xFF;
	
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
	#[allow(dead_code)]
	const HubClass: u8 = 0x09;
	#[allow(dead_code)]
	const HubStorageSubClass: u8 = 0x00;
	#[allow(dead_code)]
	const HubStorageFullSpeedHubProtocol: u8 = 0x00;
	#[allow(dead_code)]
	const HubStorageHiSpeedHubWithSingleTTProtocol: u8 = 0x01;
	#[allow(dead_code)]
	const HubStorageHiSpeedHubWithMultipleTTsProtocol: u8 = 0x02;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass11h>.
	#[allow(dead_code)]
	const BillboardDeviceClass: u8 = 0x12;
	#[allow(dead_code)]
	const BillboardDeviceSubClass: u8 = 0x00;
	#[allow(dead_code)]
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
}

impl ClassAndProtocol<AlternateSetting>
{
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
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Bh>.
	pub(crate) const SmartCardClass: u8 = 0x0B;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Dh>.
	#[allow(dead_code)]
	const ContentSecurityClass: u8 = 0x0D;
	#[allow(dead_code)]
	const ContentSecuritySubClass: u8 = 0x00;
	#[allow(dead_code)]
	const ContentSecurityProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Eh>.
	#[allow(dead_code)]
	const VideoClass: u8 = 0x0E;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Fh>.
	#[allow(dead_code)]
	const PersonalHealthcareClass: u8 = 0x0F;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass10h>.
	#[allow(dead_code)]
	const AudioVideoDevicesClass: u8 = 0x10;
	#[allow(dead_code)]
	const AudioVideoControlSubClass: u8 = 0x01;
	#[allow(dead_code)]
	const AudioVideoControlSubClassProtocol: u8 = 0x00;
	#[allow(dead_code)]
	const AudioVideoVideoStreamingSubClass: u8 = 0x02;
	#[allow(dead_code)]
	const AudioVideoVideoStreamingSubClassProtocol: u8 = 0x00;
	#[allow(dead_code)]
	const AudioVideoAudioStreamingSubClass: u8 = 0x03;
	#[allow(dead_code)]
	const AudioVideoAudioStreamingSubClassProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass12h>.
	#[allow(dead_code)]
	const UsbTypeCBridgeClass: u8 = 0x12;
	#[allow(dead_code)]
	const UsbTypeCBridgeSubClass: u8 = 0x00;
	#[allow(dead_code)]
	const UsbTypeCBridgeProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassE0h>.
	#[allow(dead_code)]
	const WirelessControllerClass: u8 = 0xE0;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassFEh>.
	#[allow(dead_code)]
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
