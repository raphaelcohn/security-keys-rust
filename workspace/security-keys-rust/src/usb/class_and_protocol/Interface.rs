// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct Interface;

impl DeviceOrInterface for Interface
{
}

impl Interface
{
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass01h>.
	pub(crate) const AudioClass: u8 = 0x01;
	
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
	pub(crate) const PhysicalClass: u8 = 0x05;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass06h>.
	pub(crate) const StillImagingClass: u8 = 0x06;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass07h>.
	pub(crate) const PrinterClass: u8 = 0x07;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass08h>.
	pub(crate) const MassStorageClass: u8 = 0x08;
	pub(crate) const MassStorageSubClass: u8 = 0x00;
	pub(crate) const MassStorageFullSpeedHubProtocol: u8 = 0x00;
	pub(crate) const MassStorageHiSpeedHubWithSingleTTProtocol: u8 = 0x01;
	pub(crate) const MassStorageHiSpeedHubWithMultipleTTsProtocol: u8 = 0x02;
	
	/// Communications Device Class (CDC) Data.
	///
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Ah>.
	pub(crate) const CommunicationsDeviceClassDataClass: u8 = 0x0A;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Bh>.
	pub(crate) const SmartCardClass: u8 = 0x0B;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Dh>.
	pub(crate) const ContentSecurityClass: u8 = 0x0D;
	pub(crate) const ContentSecuritySubClass: u8 = 0x00;
	pub(crate) const ContentSecurityProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Eh>.
	pub(crate) const VideoClass: u8 = 0x0E;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Fh>.
	pub(crate) const PersonalHealthcareClass: u8 = 0x0F;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass10h>.
	pub(crate) const AudioVideoDevicesClass: u8 = 0x10;
	pub(crate) const AudioVideoControlSubClass: u8 = 0x01;
	pub(crate) const AudioVideoControlSubClassProtocol: u8 = 0x00;
	pub(crate) const AudioVideoVideoStreamingSubClass: u8 = 0x02;
	pub(crate) const AudioVideoVideoStreamingSubClassProtocol: u8 = 0x00;
	pub(crate) const AudioVideoAudioStreamingSubClass: u8 = 0x03;
	pub(crate) const AudioVideoAudioStreamingSubClassProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass12h>.
	pub(crate) const UsbTypeCBridgeClass: u8 = 0x12;
	pub(crate) const UsbTypeCBridgeSubClass: u8 = 0x00;
	pub(crate) const UsbTypeCBridgeProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassE0h>.
	pub(crate) const WirelessControllerClass: u8 = 0xE0;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassFEh>.
	pub(crate) const ApplicationSpecificClass: u8 = 0xFE;
}
