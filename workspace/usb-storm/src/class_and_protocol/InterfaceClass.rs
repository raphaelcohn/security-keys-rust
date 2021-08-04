// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Interface class code.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum InterfaceClass
{
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass01h>.
	Audio(AudioSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass02h>.
	CommunicationsDeviceClassControl(UnrecognizedSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass03h>.
	HumanInterfaceDevice(HumanInterfaceDeviceInterfaceSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass05h>.
	Physical(UnrecognizedSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass06h>.
	StillImaging(UnrecognizedSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass07h>.
	Printer(UnrecognizedSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass08h>.
	MassStorage(UnrecognizedSubClass),
	
	/// Communications Device Class (CDC) Data.
	///
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Ah>.
	CommunicationsDeviceClassData(UnrecognizedSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Bh>.
	SmartCard(SmartCardInterfaceSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Dh>.
	ContentSecurity(KnownOrUnrecognizedSubClassAndProtocol),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Eh>.
	Video(VideoSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Fh>.
	PersonalHealthcare(UnrecognizedSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass10h>.
	AudioVideo(AudioVideoInterfaceSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass12h>.
	UsbTypeCBridgeDevice(KnownOrUnrecognizedSubClassAndProtocol),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassDCh>.
	DiagnosticDevice(DiagnosticSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassE0h>.
	WirelessController(WirelessControllerSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassEFh>.
	Miscellaneous(MiscellaneousInterfaceSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassFEh>.
	ApplicationSpecific(ApplicationSpecificInterfaceSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassFFh>.
	VendorSpecific(UnrecognizedSubClass),
	
	/// Should be a device-only class code.
	ShouldBeDeviceOnly
	{
		#[allow(missing_docs)]
		class_code: u8,
		
		#[allow(missing_docs)]
		#[serde(flatten)]
		sub_class: UnrecognizedSubClass,
	},
	
	#[allow(missing_docs)]
	Unrecognized
	{
		class_code: u8,
		
		#[serde(flatten)]
		sub_class: UnrecognizedSubClass,
	},
}

impl InterfaceClass
{
	#[allow(unused_qualifications)]
	#[inline(always)]
	pub(crate) fn parse(alternate_setting: &libusb_interface_descriptor) -> Self
	{
		use ApplicationSpecificInterfaceSubClass::*;
		use AudioVideoInterfaceSubClass::Control;
		use AudioVideoInterfaceSubClass::DataVideoStreamingInterface;
		use AudioVideoInterfaceSubClass::DataAudioStreamingInterface;
		use BluetoothProtocol::*;
		use DebugDiagnosticProtocol::*;
		use DiagnosticProtocol::*;
		use DiagnosticSubClass::*;
		use DvbCommonInterfaceProtocol::*;
		use InterfaceClass::*;
		use HumanInterfaceDeviceInterfaceSubClass::Boot;
		use HumanInterfaceDeviceInterfaceBootProtocol::Keyboard;
		use HumanInterfaceDeviceInterfaceBootProtocol::Mouse;
		use MiscellaneousInterfaceSubClass::*;
		use SmartCardInterfaceSubClass::Known;
		use SmartCardProtocol::*;
		use StreamTransportEfficientProtocol::*;
		use SyncProtocol::*;
		use TestAndMeasurementProtocol::*;
		use Usb3VisionControlProtocol::*;
		use WireAdapterProtocol::*;
		use WirelessControllerSubClass::Bluetooth;
		use WirelessControllerSubClass::WireAdapter;
		
		let class_code = alternate_setting.bInterfaceClass;
		let sub_class_code = alternate_setting.bInterfaceSubClass;
		let protocol_code = alternate_setting.bInterfaceProtocol;
		
		match (class_code, sub_class_code, protocol_code)
		{
			(0x00, _, _) => InterfaceClass::Unrecognized { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x01, 0x01, 0x00) => Audio(AudioSubClass::Control(AudioProtocol::Version_1_0)),
			(0x01, 0x01, 0x20) => Audio(AudioSubClass::Control(AudioProtocol::Version_2_0)),
			(0x01, 0x01, 0x30) => Audio(AudioSubClass::Control(AudioProtocol::Version_3_0)),
			(0x01, 0x01, _) => Audio(AudioSubClass::Control(AudioProtocol::Unrecognized(protocol_code))),
			(0x01, 0x02, 0x00) => Audio(AudioSubClass::Streaming(AudioProtocol::Version_1_0)),
			(0x01, 0x02, 0x20) => Audio(AudioSubClass::Streaming(AudioProtocol::Version_2_0)),
			(0x01, 0x02, 0x30) => Audio(AudioSubClass::Streaming(AudioProtocol::Version_3_0)),
			(0x01, 0x02, _) => Audio(AudioSubClass::Streaming(AudioProtocol::Unrecognized(protocol_code))),
			(0x01, 0x03, 0x00) => Audio(AudioSubClass::MidiStreaming(KnownOrUnrecognizedProtocol::Known)),
			(0x01, 0x03, _) => Audio(AudioSubClass::MidiStreaming(KnownOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x01, _, _) => Audio(AudioSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x02, _, _) => CommunicationsDeviceClassControl(UnrecognizedSubClass { sub_class_code, protocol_code }),
			
			(0x03, 0x00, 0x00) => HumanInterfaceDevice(HumanInterfaceDeviceInterfaceSubClass::None { unknown_protocol: None }),
			(0x03, 0x00, _) => HumanInterfaceDevice(HumanInterfaceDeviceInterfaceSubClass::None { unknown_protocol: Some(new_non_zero_u8(protocol_code)) }),
			(0x03, 0x01, 0x00) => HumanInterfaceDevice(Boot(HumanInterfaceDeviceInterfaceBootProtocol::None)),
			(0x03, 0x01, 0x01) => HumanInterfaceDevice(Boot(Keyboard)),
			(0x03, 0x01, 0x02) => HumanInterfaceDevice(Boot(Mouse)),
			(0x03, 0x01, _) => HumanInterfaceDevice(Boot(HumanInterfaceDeviceInterfaceBootProtocol::Unrecognized(protocol_code))),
			(0x03, _, _) => HumanInterfaceDevice(HumanInterfaceDeviceInterfaceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x04, _, _) => InterfaceClass::Unrecognized { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x05, _, _) => Physical(UnrecognizedSubClass { sub_class_code, protocol_code }),
			
			(0x06, _, _) => StillImaging(UnrecognizedSubClass { sub_class_code, protocol_code }),
			
			(0x07, _, _) => Printer(UnrecognizedSubClass { sub_class_code, protocol_code }),
			
			(0x08, _, _) => MassStorage(UnrecognizedSubClass { sub_class_code, protocol_code }),
			
			(0x09, _, _) => ShouldBeDeviceOnly { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x0A, _, _) => CommunicationsDeviceClassData(UnrecognizedSubClass { sub_class_code, protocol_code }),
			
			(0x0B, 0x00, 0x00) => SmartCard(Known(BulkTransfer)),
			(0x0B, 0x00, 0x01) => SmartCard(Known(IccdVersionA)),
			(0x0B, 0x00, 0x02) => SmartCard(Known(IccdVersionB)),
			(0x0B, _, _) => SmartCard(SmartCardInterfaceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x0C, _, _) => InterfaceClass::Unrecognized { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x0D, 0x00, 0x00) => ContentSecurity(KnownOrUnrecognizedSubClassAndProtocol::Known),
			
			(0x0D, _, _) => ContentSecurity(KnownOrUnrecognizedSubClassAndProtocol::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),

			(0x0E, 0x01, 0x01) => Video(VideoSubClass::Control),
			(0x0E, 0x02, 0x01) => Video(VideoSubClass::Streaming),
			(0x0E, 0x03, 0x00) => Video(VideoSubClass::InterfaceCollection),
			(0x0E, _, _) => Video(VideoSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x0F, _, _) => PersonalHealthcare(UnrecognizedSubClass { sub_class_code, protocol_code }),
			
			(0x10, 0x01, 0x00) => AudioVideo(Control(None)),
			(0x10, 0x01, _) => AudioVideo(Control(Some(new_non_zero_u8(protocol_code)))),
			(0x10, 0x02, 0x00) => AudioVideo(DataVideoStreamingInterface(None)),
			(0x10, 0x02, _) => AudioVideo(DataVideoStreamingInterface(Some(new_non_zero_u8(protocol_code)))),
			(0x10, 0x03, 0x00) => AudioVideo(DataAudioStreamingInterface(None)),
			(0x10, 0x04, _) => AudioVideo(DataAudioStreamingInterface(Some(new_non_zero_u8(protocol_code)))),
			(0x10, _, _) => AudioVideo(AudioVideoInterfaceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x11, _, _) => ShouldBeDeviceOnly { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x12, 0x00, 0x00) => UsbTypeCBridgeDevice(KnownOrUnrecognizedSubClassAndProtocol::Known),
			(0x12, _, _) => UsbTypeCBridgeDevice(KnownOrUnrecognizedSubClassAndProtocol::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x13 ..= 0xDB, _, _) => InterfaceClass::Unrecognized { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0xDC, 0x00, _) => DiagnosticDevice(DiagnosticSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			(0xDC, 0x01, 0x00) => DiagnosticDevice(Usb2Compliance(KnownOrUnrecognizedProtocol::Unrecognized(0x00))),
			(0xDC, 0x01, 0x01) => DiagnosticDevice(Usb2Compliance(KnownOrUnrecognizedProtocol::Known)),
			(0xDC, 0x01, _) => DiagnosticDevice(Usb2Compliance(KnownOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0xDC, 0x02, 0x00) => DiagnosticDevice(Debug(TargetVendorDefined)),
			(0xDC, 0x02, 0x01) => DiagnosticDevice(Debug(GnuRemoteDebugCommandSet)),
			(0xDC, 0x02, _) => DiagnosticDevice(Debug(DebugDiagnosticProtocol::UnrecognizedProtocol(new_non_zero_u8(protocol_code)))),
			(0xDC, 0x03, 0x00) => DiagnosticDevice(TraceOnDbC(Undefined)),
			(0xDC, 0x03, 0x01) => DiagnosticDevice(TraceOnDbC(VendorDefined)),
			(0xDC, 0x03, _) => DiagnosticDevice(TraceOnDbC(DiagnosticProtocol::UnrecognizedProtocol(new_non_zero_u8(protocol_code)))),
			(0xDC, 0x04, 0x00) => DiagnosticDevice(DfxOnDbC(Undefined)),
			(0xDC, 0x04, 0x01) => DiagnosticDevice(DfxOnDbC(VendorDefined)),
			(0xDC, 0x04, _) => DiagnosticDevice(DfxOnDbC(DiagnosticProtocol::UnrecognizedProtocol(new_non_zero_u8(protocol_code)))),
			(0xDC, 0x05, 0x00) => DiagnosticDevice(TraceOverGeneralPurposeEndPointOnDvC(TraceOverGeneralPurposeEndPointOnDvCDiagnosticProtocol::VendorDefined)),
			(0xDC, 0x05, 0x01) => DiagnosticDevice(TraceOverGeneralPurposeEndPointOnDvC(TraceOverGeneralPurposeEndPointOnDvCDiagnosticProtocol::Gnu)),
			(0xDC, 0x05, _) => DiagnosticDevice(TraceOverGeneralPurposeEndPointOnDvC(TraceOverGeneralPurposeEndPointOnDvCDiagnosticProtocol::UnrecognizedProtocol(new_non_zero_u8(protocol_code)))),
			(0xDC, 0x06, 0x00) => DiagnosticDevice(DfxOnDvC(Undefined)),
			(0xDC, 0x06, 0x01) => DiagnosticDevice(DfxOnDvC(VendorDefined)),
			(0xDC, 0x06, _) => DiagnosticDevice(DfxOnDvC(DiagnosticProtocol::UnrecognizedProtocol(new_non_zero_u8(protocol_code)))),
			(0xDC, 0x07, 0x00) => DiagnosticDevice(TraceOnDvC(Undefined)),
			(0xDC, 0x07, 0x01) => DiagnosticDevice(TraceOnDvC(VendorDefined)),
			(0xDC, 0x07, _) => DiagnosticDevice(TraceOnDvC(DiagnosticProtocol::UnrecognizedProtocol(new_non_zero_u8(protocol_code)))),
			(0xDC, 0x08, 0x00) => DiagnosticDevice(DiagnosticSubClass::Miscellaneous(KnownOrUnrecognizedProtocol::Known)),
			(0xDC, 0x08, _) => DiagnosticDevice(DiagnosticSubClass::Miscellaneous(KnownOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0xDC, _, _) => DiagnosticDevice(DiagnosticSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0xDD ..= 0xDF, _, _) => InterfaceClass::Unrecognized { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0xE0, 0x01, 0x00) => WirelessController(Bluetooth(BluetoothProtocol::UnrecognizedProtocol(0x00))),
			(0xE0, 0x01, 0x01) => WirelessController(Bluetooth(ProgrammingInterface)),
			(0xE0, 0x01, 0x02) => WirelessController(Bluetooth(UwbRadioControlInterface)),
			(0xE0, 0x01, 0x03) => WirelessController(Bluetooth(RemoteNdis)),
			(0xE0, 0x01, 0x04) => WirelessController(Bluetooth(AmpController)),
			(0xE0, 0x01, _) => WirelessController(Bluetooth(BluetoothProtocol::UnrecognizedProtocol(protocol_code))),
			(0xE0, 0x02, 0x00) => WirelessController(WireAdapter(WireAdapterProtocol::UnrecognizedProtocol(0x00))),
			(0xE0, 0x02, 0x01) => WirelessController(WireAdapter(HostWireControlDataInterface)),
			(0xE0, 0x02, 0x02) => WirelessController(WireAdapter(DeviceWireControlDataInterface)),
			(0xE0, 0x02, 0x03) => WirelessController(WireAdapter(DeviceWireIsochronousInterface)),
			(0xE0, 0x02, _) => WirelessController(WireAdapter(WireAdapterProtocol::UnrecognizedProtocol(0x00))),
			(0xE0, _, _) => WirelessController(WirelessControllerSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0xE1 ..= 0xEE, _, _) => InterfaceClass::Unrecognized { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0xEF, 0x00, _) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			(0xEF, 0x01, 0x00) => InterfaceClass::Miscellaneous(Sync(SyncProtocol::UnrecognizedProtocol(0x00))),
			(0xEF, 0x01, 0x01) => InterfaceClass::Miscellaneous(Sync(Active)),
			(0xEF, 0x01, 0x02) => InterfaceClass::Miscellaneous(Sync(Palm)),
			(0xEF, 0x01, _) => InterfaceClass::Miscellaneous(Sync(SyncProtocol::UnrecognizedProtocol(protocol_code))),
			(0xEF, 0x02, _) => ShouldBeDeviceOnly { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			(0xEF, 0x03, 0x00) => InterfaceClass::Miscellaneous(CableBasedAssociationFramework(KnownOrUnrecognizedProtocol::Unrecognized(0x00))),
			(0xEF, 0x03, 0x01) => InterfaceClass::Miscellaneous(CableBasedAssociationFramework(KnownOrUnrecognizedProtocol::Known)),
			(0xEF, 0x03, _) => InterfaceClass::Miscellaneous(CableBasedAssociationFramework(KnownOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0xEF, 0x04, 0x00) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::RemoteNetworkDriverInterfaceSpecificationProtocol(self::RemoteNetworkDriverInterfaceSpecificationProtocol::UnrecognizedProtocol(0x00))),
			(0xEF, 0x04, 0x01) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::RemoteNetworkDriverInterfaceSpecificationProtocol(self::RemoteNetworkDriverInterfaceSpecificationProtocol::OverEthernet)),
			(0xEF, 0x04, 0x02) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::RemoteNetworkDriverInterfaceSpecificationProtocol(self::RemoteNetworkDriverInterfaceSpecificationProtocol::OverWiFi)),
			(0xEF, 0x04, 0x03) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::RemoteNetworkDriverInterfaceSpecificationProtocol(self::RemoteNetworkDriverInterfaceSpecificationProtocol::OverWiMax)),
			(0xEF, 0x04, 0x04) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::RemoteNetworkDriverInterfaceSpecificationProtocol(self::RemoteNetworkDriverInterfaceSpecificationProtocol::OverWWan)),
			(0xEF, 0x04, 0x05) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::RemoteNetworkDriverInterfaceSpecificationProtocol(self::RemoteNetworkDriverInterfaceSpecificationProtocol::OverRawIpV4)),
			(0xEF, 0x04, 0x06) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::RemoteNetworkDriverInterfaceSpecificationProtocol(self::RemoteNetworkDriverInterfaceSpecificationProtocol::OverRawIpV6)),
			(0xEF, 0x04, 0x07) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::RemoteNetworkDriverInterfaceSpecificationProtocol(self::RemoteNetworkDriverInterfaceSpecificationProtocol::OverGprs)),
			(0xEF, 0x04, _) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::RemoteNetworkDriverInterfaceSpecificationProtocol(self::RemoteNetworkDriverInterfaceSpecificationProtocol::UnrecognizedProtocol(protocol_code))),
			(0xEF, 0x05, 0x00) => InterfaceClass::Miscellaneous(Usb3Vision(ControlInterface)),
			(0xEF, 0x05, 0x01) => InterfaceClass::Miscellaneous(Usb3Vision(EventInterface)),
			(0xEF, 0x05, 0x02) => InterfaceClass::Miscellaneous(Usb3Vision(StreamingInterface)),
			(0xEF, 0x05, _) => InterfaceClass::Miscellaneous(Usb3Vision(Usb3VisionControlProtocol::UnrecognizedProtocol(new_non_zero_u8(protocol_code)))),
			(0xEF, 0x06, 0x00) => InterfaceClass::Miscellaneous(StreamTransportEfficientProtocolForContentProtection(StreamTransportEfficientProtocol::UnrecognizedProtocol(0x00))),
			(0xEF, 0x06, 0x01) => InterfaceClass::Miscellaneous(StreamTransportEfficientProtocolForContentProtection(Ordinary)),
			(0xEF, 0x06, 0x02) => InterfaceClass::Miscellaneous(StreamTransportEfficientProtocolForContentProtection(Raw)),
			(0xEF, 0x06, _) => InterfaceClass::Miscellaneous(StreamTransportEfficientProtocolForContentProtection(StreamTransportEfficientProtocol::UnrecognizedProtocol(protocol_code))),
			(0xEF, 0x07, 0x00) => InterfaceClass::Miscellaneous(DvbCommonInterface(DvbCommonInterfaceProtocol::UnrecognizedProtocol(0x00))),
			(0xEF, 0x07, 0x01) => InterfaceClass::Miscellaneous(DvbCommonInterface(CommandInterface)),
			(0xEF, 0x07, 0x02) => InterfaceClass::Miscellaneous(DvbCommonInterface(MediaInterface)),
			(0xEF, 0x07, _) => InterfaceClass::Miscellaneous(DvbCommonInterface(DvbCommonInterfaceProtocol::UnrecognizedProtocol(protocol_code))),
			(0xEF, _, _) => InterfaceClass::Miscellaneous(MiscellaneousInterfaceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0xF0 ..= 0xFD, _, _) => InterfaceClass::Unrecognized { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0xFE, 0x00, _) => ApplicationSpecific(Unrecognised(UnrecognizedSubClass { sub_class_code, protocol_code })),
			(0xFE, 0x01, 0x00) => ApplicationSpecific(DeviceFirmwareUpgrade(KnownOrUnrecognizedProtocol::Unrecognized(0x00))),
			(0xFE, 0x01, 0x01) => ApplicationSpecific(DeviceFirmwareUpgrade(KnownOrUnrecognizedProtocol::Known)),
			(0xFE, 0x01, _) => ApplicationSpecific(DeviceFirmwareUpgrade(KnownOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0xFE, 0x02, 0x00) => ApplicationSpecific(IrdaBridgeDevice(KnownOrUnrecognizedProtocol::Known)),
			(0xFE, 0x02, _) => ApplicationSpecific(IrdaBridgeDevice(KnownOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0xFE, 0x03, 0x00) => ApplicationSpecific(TestAndMeasurementDevice(Normal)),
			(0xFE, 0x03, 0x01) => ApplicationSpecific(TestAndMeasurementDevice(USBTMC_USB488)),
			(0xFE, 0x03, _) => ApplicationSpecific(TestAndMeasurementDevice(TestAndMeasurementProtocol::UnrecognizedProtocol(new_non_zero_u8(protocol_code)))),
			(0xFE, _, _) => ApplicationSpecific(Unrecognised(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0xFF, _, _) => VendorSpecific(UnrecognizedSubClass { sub_class_code, protocol_code }),
		}
	}
}
