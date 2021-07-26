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
	const AudioClass: u8 = 0x01;
	
	/// Human Interface Device (HID).
	///
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass03h>.
	const HumanInterfaceDeviceClass: u8 = 0x03;
	
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
	const SmartCardClass: u8 = 0x0B;
	
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
}
