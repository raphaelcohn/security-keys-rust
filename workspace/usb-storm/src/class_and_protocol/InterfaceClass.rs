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
	CommunicationsDeviceClassControl(CommunicationsDeviceClassControlSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass03h>.
	HumanInterfaceDevice(HumanInterfaceDeviceInterfaceSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass05h>.
	Physical(UnrecognizedSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass06h>.
	StillImaging(UnrecognizedSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass07h>.
	Printer(PrinterSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass08h>.
	MassStorage(MassStorageSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass09h>.
	Hub(HubSubClass),
	
	/// Communications Device Class (CDC) Data.
	///
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Ah>.
	CommunicationsDeviceClassData(CommunicationsDeviceClassDataSubClassAndProtocol),
	
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
		use CommunicationsDeviceClassControlSubClass::*;
		use PublicSwitchedTelephoneNetworkProtocol::*;
		use WirelessProtocol::*;
		use CommunicationsDeviceClassDataSubClassAndProtocol::*;
		use MassStorageProtocol::*;
		
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
			
			(0x02, 0x00, _) => CommunicationsDeviceClassControl(Reserved0x00 { protocol_code }),
			(0x02, 0x01, 0x00) => CommunicationsDeviceClassControl(DirectLineControlModel(PublicSwitchedTelephoneNetworkProtocol::Unrecognized { protocol_code })),
			(0x02, 0x01, 0x01) => CommunicationsDeviceClassControl(DirectLineControlModel(ITU_T_V_250)),
			(0x02, 0x01, 0x02 ..= 0xFE) => CommunicationsDeviceClassControl(DirectLineControlModel(PublicSwitchedTelephoneNetworkProtocol::Unrecognized { protocol_code })),
			(0x02, 0x01, 0xFF) => CommunicationsDeviceClassControl(DirectLineControlModel(PublicSwitchedTelephoneNetworkProtocol::VendorSpecific)),
			(0x02, 0x02, 0x00) => CommunicationsDeviceClassControl(AbstractControlModel(PublicSwitchedTelephoneNetworkProtocol::Unrecognized { protocol_code })),
			(0x02, 0x02, 0x01) => CommunicationsDeviceClassControl(AbstractControlModel(ITU_T_V_250)),
			(0x02, 0x02, 0x02 ..= 0xFE) => CommunicationsDeviceClassControl(AbstractControlModel(PublicSwitchedTelephoneNetworkProtocol::Unrecognized { protocol_code })),
			(0x02, 0x02, 0xFF) => CommunicationsDeviceClassControl(AbstractControlModel(PublicSwitchedTelephoneNetworkProtocol::VendorSpecific)),
			(0x02, 0x03, 0x00) => CommunicationsDeviceClassControl(TelephoneControlModel(PublicSwitchedTelephoneNetworkProtocol::Unrecognized { protocol_code })),
			(0x02, 0x03, 0x01) => CommunicationsDeviceClassControl(TelephoneControlModel(ITU_T_V_250)),
			(0x02, 0x03, 0x02 ..= 0xFE) => CommunicationsDeviceClassControl(TelephoneControlModel(PublicSwitchedTelephoneNetworkProtocol::Unrecognized { protocol_code })),
			(0x02, 0x03, 0xFF) => CommunicationsDeviceClassControl(TelephoneControlModel(PublicSwitchedTelephoneNetworkProtocol::VendorSpecific)),
			(0x02, 0x04, 0x00) => CommunicationsDeviceClassControl(MultiChannelControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Known)),
			(0x02, 0x04, 0x01 ..= 0xFE) => CommunicationsDeviceClassControl(MultiChannelControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x02, 0x04, 0xFF) => CommunicationsDeviceClassControl(MultiChannelControlModel(KnownVendorSpecificOrUnrecognizedProtocol::VendorSpecific)),
			(0x02, 0x05, 0x00) => CommunicationsDeviceClassControl(CapiControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Known)),
			(0x02, 0x05, 0x01 ..= 0xFE) => CommunicationsDeviceClassControl(CapiControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x02, 0x05, 0xFF) => CommunicationsDeviceClassControl(CapiControlModel(KnownVendorSpecificOrUnrecognizedProtocol::VendorSpecific)),
			(0x02, 0x06, 0x00) => CommunicationsDeviceClassControl(EthernetControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Known)),
			(0x02, 0x06, 0x01 ..= 0xFE) => CommunicationsDeviceClassControl(EthernetControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x02, 0x06, 0xFF) => CommunicationsDeviceClassControl(EthernetControlModel(KnownVendorSpecificOrUnrecognizedProtocol::VendorSpecific)),
			(0x02, 0x07, 0x00) => CommunicationsDeviceClassControl(AsynchronousTransferModeControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Known)),
			(0x02, 0x07, 0x01 ..= 0xFE) => CommunicationsDeviceClassControl(AsynchronousTransferModeControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x02, 0x07, 0xFF) => CommunicationsDeviceClassControl(AsynchronousTransferModeControlModel(KnownVendorSpecificOrUnrecognizedProtocol::VendorSpecific)),
			(0x02, 0x08, 0x00 ..= 0x01) => CommunicationsDeviceClassControl(WirelessHandsetControlModel(WirelessProtocol::Unrecognized { protocol_code })),
			(0x02, 0x08, 0x02) => CommunicationsDeviceClassControl(WirelessHandsetControlModel(PCCA_101)),
			(0x02, 0x08, 0x03) => CommunicationsDeviceClassControl(WirelessHandsetControlModel(PCCA_101_and_Annex_O)),
			(0x02, 0x08, 0x04) => CommunicationsDeviceClassControl(WirelessHandsetControlModel(GSM_07_07)),
			(0x02, 0x08, 0x05) => CommunicationsDeviceClassControl(WirelessHandsetControlModel(_3GPP_27_007)),
			(0x02, 0x08, 0x06) => CommunicationsDeviceClassControl(WirelessHandsetControlModel(TIA_for_CDMA_C_S0017_0)),
			(0x02, 0x08, 0x07 ..= 0xFD) => CommunicationsDeviceClassControl(WirelessHandsetControlModel(WirelessProtocol::Unrecognized { protocol_code })),
			(0x02, 0x08, 0xFE) => CommunicationsDeviceClassControl(WirelessHandsetControlModel(ExternalProtocol)),
			(0x02, 0x08, 0xFF) => CommunicationsDeviceClassControl(WirelessHandsetControlModel(WirelessProtocol::VendorSpecific)),
			(0x02, 0x09, 0x00 ..= 0x01) => CommunicationsDeviceClassControl(DeviceManagementModel(WirelessProtocol::Unrecognized { protocol_code })),
			(0x02, 0x09, 0x02) => CommunicationsDeviceClassControl(DeviceManagementModel(PCCA_101)),
			(0x02, 0x09, 0x03) => CommunicationsDeviceClassControl(DeviceManagementModel(PCCA_101_and_Annex_O)),
			(0x02, 0x09, 0x04) => CommunicationsDeviceClassControl(DeviceManagementModel(GSM_07_07)),
			(0x02, 0x09, 0x05) => CommunicationsDeviceClassControl(DeviceManagementModel(_3GPP_27_007)),
			(0x02, 0x09, 0x06) => CommunicationsDeviceClassControl(DeviceManagementModel(TIA_for_CDMA_C_S0017_0)),
			(0x02, 0x09, 0x07 ..= 0xFD) => CommunicationsDeviceClassControl(DeviceManagementModel(WirelessProtocol::Unrecognized { protocol_code })),
			(0x02, 0x09, 0xFE) => CommunicationsDeviceClassControl(DeviceManagementModel(ExternalProtocol)),
			(0x02, 0x09, 0xFF) => CommunicationsDeviceClassControl(DeviceManagementModel(WirelessProtocol::VendorSpecific)),
			(0x02, 0x0A, 0x00 ..= 0x01) => CommunicationsDeviceClassControl(MobileDirectLineModel(WirelessProtocol::Unrecognized { protocol_code })),
			(0x02, 0x0A, 0x02) => CommunicationsDeviceClassControl(MobileDirectLineModel(PCCA_101)),
			(0x02, 0x0A, 0x03) => CommunicationsDeviceClassControl(MobileDirectLineModel(PCCA_101_and_Annex_O)),
			(0x02, 0x0A, 0x04) => CommunicationsDeviceClassControl(MobileDirectLineModel(GSM_07_07)),
			(0x02, 0x0A, 0x05) => CommunicationsDeviceClassControl(MobileDirectLineModel(_3GPP_27_007)),
			(0x02, 0x0A, 0x06) => CommunicationsDeviceClassControl(MobileDirectLineModel(TIA_for_CDMA_C_S0017_0)),
			(0x02, 0x0A, 0x07 ..= 0xFD) => CommunicationsDeviceClassControl(MobileDirectLineModel(WirelessProtocol::Unrecognized { protocol_code })),
			(0x02, 0x0A, 0xFE) => CommunicationsDeviceClassControl(MobileDirectLineModel(ExternalProtocol)),
			(0x02, 0x0A, 0xFF) => CommunicationsDeviceClassControl(MobileDirectLineModel(WirelessProtocol::VendorSpecific)),
			(0x02, 0x0B, 0x00 ..= 0x01) => CommunicationsDeviceClassControl(OBjectEXchange(WirelessProtocol::Unrecognized { protocol_code })),
			(0x02, 0x0B, 0x02) => CommunicationsDeviceClassControl(OBjectEXchange(PCCA_101)),
			(0x02, 0x0B, 0x03) => CommunicationsDeviceClassControl(OBjectEXchange(PCCA_101_and_Annex_O)),
			(0x02, 0x0B, 0x04) => CommunicationsDeviceClassControl(OBjectEXchange(GSM_07_07)),
			(0x02, 0x0B, 0x05) => CommunicationsDeviceClassControl(OBjectEXchange(_3GPP_27_007)),
			(0x02, 0x0B, 0x06) => CommunicationsDeviceClassControl(OBjectEXchange(TIA_for_CDMA_C_S0017_0)),
			(0x02, 0x0B, 0x07 ..= 0xFD) => CommunicationsDeviceClassControl(OBjectEXchange(WirelessProtocol::Unrecognized { protocol_code })),
			(0x02, 0x0B, 0xFE) => CommunicationsDeviceClassControl(OBjectEXchange(ExternalProtocol)),
			(0x02, 0x0B, 0xFF) => CommunicationsDeviceClassControl(OBjectEXchange(WirelessProtocol::VendorSpecific)),
			(0x02, 0x0C, 0x00 ..= 0x06) => CommunicationsDeviceClassControl(EthernetEmulationModel(KnownVendorSpecificOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x02, 0x0C, 0x07) => CommunicationsDeviceClassControl(EthernetEmulationModel(KnownVendorSpecificOrUnrecognizedProtocol::Known)),
			(0x02, 0x0C, 0x08 ..= 0xFE) => CommunicationsDeviceClassControl(EthernetEmulationModel(KnownVendorSpecificOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x02, 0x0C, 0xFF) => CommunicationsDeviceClassControl(EthernetEmulationModel(KnownVendorSpecificOrUnrecognizedProtocol::VendorSpecific)),
			(0x02, 0x0D, 0x00) => CommunicationsDeviceClassControl(NetworkControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x02, 0x0D, 0x01) => CommunicationsDeviceClassControl(NetworkControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Known)),
			(0x02, 0x0D, 0x02 ..= 0xFE) => CommunicationsDeviceClassControl(NetworkControlModel(KnownVendorSpecificOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x02, 0x0D, 0xFF) => CommunicationsDeviceClassControl(NetworkControlModel(KnownVendorSpecificOrUnrecognizedProtocol::VendorSpecific)),
			(0x02, 0x0E, 0x00 ..= 0x01) => CommunicationsDeviceClassControl(MobileBroadbandInterfaceModel(KnownVendorSpecificOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x02, 0x0E, 0x02) => CommunicationsDeviceClassControl(MobileBroadbandInterfaceModel(KnownVendorSpecificOrUnrecognizedProtocol::Known)),
			(0x02, 0x0E, 0x03 ..= 0xFE) => CommunicationsDeviceClassControl(MobileBroadbandInterfaceModel(KnownVendorSpecificOrUnrecognizedProtocol::Unrecognized(protocol_code))),
			(0x02, 0x0E, 0xFF) => CommunicationsDeviceClassControl(MobileBroadbandInterfaceModel(KnownVendorSpecificOrUnrecognizedProtocol::VendorSpecific)),
			(0x02, 0x0F ..= 0x7F, _) => CommunicationsDeviceClassControl(CommunicationsDeviceClassControlSubClass::ReservedFutureUse { sub_class_code, protocol_code }),
			(0x02, 0x80 ..= 0xFF, _) => CommunicationsDeviceClassControl(CommunicationsDeviceClassControlSubClass::VendorSpecific { sub_class_code, protocol_code }),
			
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
			
			(0x07, 0x00, _) => Printer(PrinterSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			(0x07, 0x01, 0x00) => Printer(PrinterSubClass::Known(PrinterProtocol::ReservedUndefined)),
			(0x07, 0x01, 0x01) => Printer(PrinterSubClass::Known(PrinterProtocol::Unidirectional)),
			(0x07, 0x01, 0x02) => Printer(PrinterSubClass::Known(PrinterProtocol::Bidirectional)),
			(0x07, 0x01, 0x03) => Printer(PrinterSubClass::Known(PrinterProtocol::Ieee_1284_4_Bidirectional)),
			(0x07, 0x01, 0x04) => Printer(PrinterSubClass::Known(PrinterProtocol::InternetPrintingProtocolOverUsb)),
			(0x07, 0x01, 0x05 ..= 0x0FE) => Printer(PrinterSubClass::Known(PrinterProtocol::Reserved(protocol_code))),
			(0x07, 0x01, 0xFF) => Printer(PrinterSubClass::Known(PrinterProtocol::VendorSpecific)),
			(0x07, 0x02 ..= 0xFF, _) => Printer(PrinterSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x08, 0x00, 0x00) => MassStorage(MassStorageSubClass::ScsiCommandSetNotReported(ControlBulkInterruptTransportWithCommandCompletionInterrupt)),
			(0x08, 0x00, 0x01) => MassStorage(MassStorageSubClass::ScsiCommandSetNotReported(ControlBulkInterruptTransportWithoutCommandCompletionInterrupt)),
			(0x08, 0x00, 0x02) => MassStorage(MassStorageSubClass::ScsiCommandSetNotReported(Obsolete)),
			(0x08, 0x00, 0x03 ..= 0x4F) => MassStorage(MassStorageSubClass::ScsiCommandSetNotReported(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x00, 0x50) => MassStorage(MassStorageSubClass::ScsiCommandSetNotReported(BulkOnly)),
			(0x08, 0x00, 0x51 ..= 0x61) => MassStorage(MassStorageSubClass::ScsiCommandSetNotReported(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x00, 0x62) => MassStorage(MassStorageSubClass::ScsiCommandSetNotReported(UsbAttachedScsi)),
			(0x08, 0x00, 0x63 ..= 0xFE) => MassStorage(MassStorageSubClass::ScsiCommandSetNotReported(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x00, 0xFF) => MassStorage(MassStorageSubClass::ScsiCommandSetNotReported(MassStorageProtocol::VendorSpecific)),
			
			(0x08, 0x01, 0x00) => MassStorage(MassStorageSubClass::ReducedBlockCommands(ControlBulkInterruptTransportWithCommandCompletionInterrupt)),
			(0x08, 0x01, 0x01) => MassStorage(MassStorageSubClass::ReducedBlockCommands(ControlBulkInterruptTransportWithoutCommandCompletionInterrupt)),
			(0x08, 0x01, 0x02) => MassStorage(MassStorageSubClass::ReducedBlockCommands(Obsolete)),
			(0x08, 0x01, 0x03 ..= 0x4F) => MassStorage(MassStorageSubClass::ReducedBlockCommands(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x01, 0x50) => MassStorage(MassStorageSubClass::ReducedBlockCommands(BulkOnly)),
			(0x08, 0x01, 0x51 ..= 0x61) => MassStorage(MassStorageSubClass::ReducedBlockCommands(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x01, 0x62) => MassStorage(MassStorageSubClass::ReducedBlockCommands(UsbAttachedScsi)),
			(0x08, 0x01, 0x63 ..= 0xFE) => MassStorage(MassStorageSubClass::ReducedBlockCommands(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x01, 0xFF) => MassStorage(MassStorageSubClass::ReducedBlockCommands(MassStorageProtocol::VendorSpecific)),
			
			(0x08, 0x02, 0x00) => MassStorage(MassStorageSubClass::MultiMediaCommandSet5(ControlBulkInterruptTransportWithCommandCompletionInterrupt)),
			(0x08, 0x02, 0x01) => MassStorage(MassStorageSubClass::MultiMediaCommandSet5(ControlBulkInterruptTransportWithoutCommandCompletionInterrupt)),
			(0x08, 0x02, 0x02) => MassStorage(MassStorageSubClass::MultiMediaCommandSet5(Obsolete)),
			(0x08, 0x02, 0x03 ..= 0x4F) => MassStorage(MassStorageSubClass::MultiMediaCommandSet5(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x02, 0x50) => MassStorage(MassStorageSubClass::MultiMediaCommandSet5(BulkOnly)),
			(0x08, 0x02, 0x51 ..= 0x61) => MassStorage(MassStorageSubClass::MultiMediaCommandSet5(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x02, 0x62) => MassStorage(MassStorageSubClass::MultiMediaCommandSet5(UsbAttachedScsi)),
			(0x08, 0x02, 0x63 ..= 0xFE) => MassStorage(MassStorageSubClass::MultiMediaCommandSet5(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x02, 0xFF) => MassStorage(MassStorageSubClass::MultiMediaCommandSet5(MassStorageProtocol::VendorSpecific)),
			
			(0x08, 0x03, 0x00) => MassStorage(MassStorageSubClass::Qic_157(ControlBulkInterruptTransportWithCommandCompletionInterrupt)),
			(0x08, 0x03, 0x01) => MassStorage(MassStorageSubClass::Qic_157(ControlBulkInterruptTransportWithoutCommandCompletionInterrupt)),
			(0x08, 0x03, 0x02) => MassStorage(MassStorageSubClass::Qic_157(Obsolete)),
			(0x08, 0x03, 0x03 ..= 0x4F) => MassStorage(MassStorageSubClass::Qic_157(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x03, 0x50) => MassStorage(MassStorageSubClass::Qic_157(BulkOnly)),
			(0x08, 0x03, 0x51 ..= 0x61) => MassStorage(MassStorageSubClass::Qic_157(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x03, 0x62) => MassStorage(MassStorageSubClass::Qic_157(UsbAttachedScsi)),
			(0x08, 0x03, 0x63 ..= 0xFE) => MassStorage(MassStorageSubClass::Qic_157(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x03, 0xFF) => MassStorage(MassStorageSubClass::Qic_157(MassStorageProtocol::VendorSpecific)),
			
			(0x08, 0x04, 0x00) => MassStorage(MassStorageSubClass::UFI(ControlBulkInterruptTransportWithCommandCompletionInterrupt)),
			(0x08, 0x04, 0x01) => MassStorage(MassStorageSubClass::UFI(ControlBulkInterruptTransportWithoutCommandCompletionInterrupt)),
			(0x08, 0x04, 0x02) => MassStorage(MassStorageSubClass::UFI(Obsolete)),
			(0x08, 0x04, 0x03 ..= 0x4F) => MassStorage(MassStorageSubClass::UFI(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x04, 0x50) => MassStorage(MassStorageSubClass::UFI(BulkOnly)),
			(0x08, 0x04, 0x51 ..= 0x61) => MassStorage(MassStorageSubClass::UFI(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x04, 0x62) => MassStorage(MassStorageSubClass::UFI(UsbAttachedScsi)),
			(0x08, 0x04, 0x63 ..= 0xFE) => MassStorage(MassStorageSubClass::UFI(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x04, 0xFF) => MassStorage(MassStorageSubClass::UFI(MassStorageProtocol::VendorSpecific)),
			
			(0x08, 0x05, 0x00) => MassStorage(MassStorageSubClass::Sff_8070i(ControlBulkInterruptTransportWithCommandCompletionInterrupt)),
			(0x08, 0x05, 0x01) => MassStorage(MassStorageSubClass::Sff_8070i(ControlBulkInterruptTransportWithoutCommandCompletionInterrupt)),
			(0x08, 0x05, 0x02) => MassStorage(MassStorageSubClass::Sff_8070i(Obsolete)),
			(0x08, 0x05, 0x03 ..= 0x4F) => MassStorage(MassStorageSubClass::Sff_8070i(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x05, 0x50) => MassStorage(MassStorageSubClass::Sff_8070i(BulkOnly)),
			(0x08, 0x05, 0x51 ..= 0x61) => MassStorage(MassStorageSubClass::Sff_8070i(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x05, 0x62) => MassStorage(MassStorageSubClass::Sff_8070i(UsbAttachedScsi)),
			(0x08, 0x05, 0x63 ..= 0xFE) => MassStorage(MassStorageSubClass::Sff_8070i(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x05, 0xFF) => MassStorage(MassStorageSubClass::Sff_8070i(MassStorageProtocol::VendorSpecific)),
			
			(0x08, 0x06, 0x00) => MassStorage(MassStorageSubClass::ScsiTransparentCommandSet(ControlBulkInterruptTransportWithCommandCompletionInterrupt)),
			(0x08, 0x06, 0x01) => MassStorage(MassStorageSubClass::ScsiTransparentCommandSet(ControlBulkInterruptTransportWithoutCommandCompletionInterrupt)),
			(0x08, 0x06, 0x02) => MassStorage(MassStorageSubClass::ScsiTransparentCommandSet(Obsolete)),
			(0x08, 0x06, 0x03 ..= 0x4F) => MassStorage(MassStorageSubClass::ScsiTransparentCommandSet(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x06, 0x50) => MassStorage(MassStorageSubClass::ScsiTransparentCommandSet(BulkOnly)),
			(0x08, 0x06, 0x51 ..= 0x61) => MassStorage(MassStorageSubClass::ScsiTransparentCommandSet(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x06, 0x62) => MassStorage(MassStorageSubClass::ScsiTransparentCommandSet(UsbAttachedScsi)),
			(0x08, 0x06, 0x63 ..= 0xFE) => MassStorage(MassStorageSubClass::ScsiTransparentCommandSet(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x06, 0xFF) => MassStorage(MassStorageSubClass::ScsiTransparentCommandSet(MassStorageProtocol::VendorSpecific)),
			
			(0x08, 0x07, 0x00) => MassStorage(MassStorageSubClass::LockableStorageDevicesFeatureSpecification(ControlBulkInterruptTransportWithCommandCompletionInterrupt)),
			(0x08, 0x07, 0x01) => MassStorage(MassStorageSubClass::LockableStorageDevicesFeatureSpecification(ControlBulkInterruptTransportWithoutCommandCompletionInterrupt)),
			(0x08, 0x07, 0x02) => MassStorage(MassStorageSubClass::LockableStorageDevicesFeatureSpecification(Obsolete)),
			(0x08, 0x07, 0x03 ..= 0x4F) => MassStorage(MassStorageSubClass::LockableStorageDevicesFeatureSpecification(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x07, 0x50) => MassStorage(MassStorageSubClass::LockableStorageDevicesFeatureSpecification(BulkOnly)),
			(0x08, 0x07, 0x51 ..= 0x61) => MassStorage(MassStorageSubClass::LockableStorageDevicesFeatureSpecification(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x07, 0x62) => MassStorage(MassStorageSubClass::LockableStorageDevicesFeatureSpecification(UsbAttachedScsi)),
			(0x08, 0x07, 0x63 ..= 0xFE) => MassStorage(MassStorageSubClass::LockableStorageDevicesFeatureSpecification(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x07, 0xFF) => MassStorage(MassStorageSubClass::LockableStorageDevicesFeatureSpecification(MassStorageProtocol::VendorSpecific)),
			
			(0x08, 0x08, 0x00) => MassStorage(MassStorageSubClass::Ieee1667(ControlBulkInterruptTransportWithCommandCompletionInterrupt)),
			(0x08, 0x08, 0x01) => MassStorage(MassStorageSubClass::Ieee1667(ControlBulkInterruptTransportWithoutCommandCompletionInterrupt)),
			(0x08, 0x08, 0x02) => MassStorage(MassStorageSubClass::Ieee1667(Obsolete)),
			(0x08, 0x08, 0x03 ..= 0x4F) => MassStorage(MassStorageSubClass::Ieee1667(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x08, 0x50) => MassStorage(MassStorageSubClass::Ieee1667(BulkOnly)),
			(0x08, 0x08, 0x51 ..= 0x61) => MassStorage(MassStorageSubClass::Ieee1667(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x08, 0x62) => MassStorage(MassStorageSubClass::Ieee1667(UsbAttachedScsi)),
			(0x08, 0x08, 0x63 ..= 0xFE) => MassStorage(MassStorageSubClass::Ieee1667(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0x08, 0xFF) => MassStorage(MassStorageSubClass::Ieee1667(MassStorageProtocol::VendorSpecific)),
			
			(0x08, 0x09 ..= 0xFE, _) => MassStorage(MassStorageSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x08, 0xFF, 0x00) => MassStorage(MassStorageSubClass::VendorSpecific(ControlBulkInterruptTransportWithCommandCompletionInterrupt)),
			(0x08, 0xFF, 0x01) => MassStorage(MassStorageSubClass::VendorSpecific(ControlBulkInterruptTransportWithoutCommandCompletionInterrupt)),
			(0x08, 0xFF, 0x02) => MassStorage(MassStorageSubClass::VendorSpecific(Obsolete)),
			(0x08, 0xFF, 0x03 ..= 0x4F) => MassStorage(MassStorageSubClass::VendorSpecific(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0xFF, 0x50) => MassStorage(MassStorageSubClass::VendorSpecific(BulkOnly)),
			(0x08, 0xFF, 0x51 ..= 0x61) => MassStorage(MassStorageSubClass::VendorSpecific(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0xFF, 0x62) => MassStorage(MassStorageSubClass::VendorSpecific(UsbAttachedScsi)),
			(0x08, 0xFF, 0x63 ..= 0xFE) => MassStorage(MassStorageSubClass::VendorSpecific(MassStorageProtocol::Unrecognized(protocol_code))),
			(0x08, 0xFF, 0xFF) => MassStorage(MassStorageSubClass::VendorSpecific(MassStorageProtocol::VendorSpecific)),
			
			(0x09, 0x00, 0x00) => Hub(HubSubClass::TransactionTranslator(HubTransactionTranslatorProtocol::No)),
			(0x09, 0x00, 0x01) => Hub(HubSubClass::TransactionTranslator(HubTransactionTranslatorProtocol::Single)),
			(0x09, 0x00, 0x02) => Hub(HubSubClass::TransactionTranslator(HubTransactionTranslatorProtocol::Multiple)),
			(0x09, 0x00, 0x03) => Hub(HubSubClass::TransactionTranslator(HubTransactionTranslatorProtocol::Unrecognized { protocol_code })),
			(0x09, _, _) => Hub(HubSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x0A, 0x00, 0x00) => CommunicationsDeviceClassData(NoSpecificProtocolRequired),
			(0x0A, 0x00, 0x01) => CommunicationsDeviceClassData(NetworkTransferBlock),
			(0x0A, 0x00, 0x02) => CommunicationsDeviceClassData(NetworkTransferBlockMobileBroadbandInterfaceModel),
			(0x0A, 0x00, 0x03 ..= 0x2F) => CommunicationsDeviceClassData(CommunicationsDeviceClassDataSubClassAndProtocol::Reserved { protocol_code }),
			(0x0A, 0x00, 0x30) => CommunicationsDeviceClassData(IsdnBri),
			(0x0A, 0x00, 0x31) => CommunicationsDeviceClassData(HighLevelDataLinkControl),
			(0x0A, 0x00, 0x32) => CommunicationsDeviceClassData(Transparent),
			(0x0A, 0x00, 0x33 ..= 0x4F) => CommunicationsDeviceClassData(CommunicationsDeviceClassDataSubClassAndProtocol::Reserved { protocol_code }),
			(0x0A, 0x00, 0x50) => CommunicationsDeviceClassData(ManagementProtocolForQ921DataLinkProtocol),
			(0x0A, 0x00, 0x51) => CommunicationsDeviceClassData(DataLinkProtocolForQ921),
			(0x0A, 0x00, 0x52) => CommunicationsDeviceClassData(TeiMultiplexorForQ921DataLinkProtocol),
			(0x0A, 0x00, 0x53 ..= 0x8F) => CommunicationsDeviceClassData(CommunicationsDeviceClassDataSubClassAndProtocol::Reserved { protocol_code }),
			(0x0A, 0x00, 0x90) => CommunicationsDeviceClassData(V42bis),
			(0x0A, 0x00, 0x91) => CommunicationsDeviceClassData(EuroIsdnProtocolControl),
			(0x0A, 0x00, 0x92) => CommunicationsDeviceClassData(V120),
			(0x0A, 0x00, 0x93) => CommunicationsDeviceClassData(Capi2),
			(0x0A, 0x00, 0x94 ..= 0xFC) => CommunicationsDeviceClassData(CommunicationsDeviceClassDataSubClassAndProtocol::Reserved { protocol_code }),
			(0x0A, 0x00, 0xFD) => CommunicationsDeviceClassData(HostBasedDriver),
			(0x0A, 0x00, 0xFE) => CommunicationsDeviceClassData(UseProtocolUnitFunctionalDescriptorsOnCommunicationsClassInterface),
			(0x0A, 0x00, 0xFF) => CommunicationsDeviceClassData(CommunicationsDeviceClassDataSubClassAndProtocol::VendorSpecific),
			(0x0A, 0x01 ..= 0xFF, _) => CommunicationsDeviceClassData(CommunicationsDeviceClassDataSubClassAndProtocol::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
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
			
			(0xFF, _, _) => InterfaceClass::VendorSpecific(UnrecognizedSubClass { sub_class_code, protocol_code }),
		}
	}
}
