// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Device class code.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DeviceClass
{
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass00h>.
	UseClassInformationInTheInterfaceDescriptors(KnownOrUnrecognizedSubClassAndProtocol),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass02h>.
	CommunicationsDeviceClassControl(UnrecognizedSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass09h>.
	Hub,
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass11h>.
	Billboard(KnownOrUnrecognizedSubClassAndProtocol),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassDCh>.
	DiagnosticDevice(DiagnosticSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassE0h>.
	Bluetooth(BluetoothProtocol),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassEFh>.
	Miscellaneous(MiscellaneousDeviceSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassFFh>.
	VendorSpecific(UnrecognizedSubClass),
	
	/// Should be an interface-only class code.
	ShouldBeInterfaceOnly
	{
		#[allow(missing_docs)]
		class_code: u8,
		
		#[allow(missing_docs)]
		#[serde(flatten)]
		unrecognized_sub_class: UnrecognizedSubClass,
	},
	
	#[allow(missing_docs)]
	Unrecognized
	{
		class_code: u8,
		
		#[serde(flatten)]
		unrecognized_sub_class: UnrecognizedSubClass,
	},
}

impl DeviceClass
{
	#[allow(unused_qualifications)]
	#[inline(always)]
	pub(crate) fn parse(device_descriptor: &libusb_device_descriptor) -> Self
	{
		use AssociationProtocol::*;
		use BluetoothProtocol::*;
		use DebugDiagnosticProtocol::*;
		use DeviceClass::*;
		use DiagnosticProtocol::*;
		use DiagnosticSubClass::*;
		use DvbCommonDeviceProtocol::*;
		use KnownOrUnrecognizedSubClassAndProtocol::Known;
		use MiscellaneousDeviceSubClass::*;
		use StreamTransportEfficientProtocol::*;
		use SyncProtocol::*;
		
		let class_code = device_descriptor.bDeviceClass;
		let sub_class_code = device_descriptor.bDeviceSubClass;
		let protocol_code = device_descriptor.bDeviceProtocol;
		
		match (class_code, sub_class_code, protocol_code)
		{
			(0x00, 0x00, 0x00) => UseClassInformationInTheInterfaceDescriptors(Known),
			(0x00, _, _) => UseClassInformationInTheInterfaceDescriptors(KnownOrUnrecognizedSubClassAndProtocol::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x01, _, _) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x02, _, _) => CommunicationsDeviceClassControl(UnrecognizedSubClass { sub_class_code, protocol_code }),
			
			(0x03, _, _) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x04, _, _) => DeviceClass::Unrecognized { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x05 ..= 0x08, _, _) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x09, _, _) => Hub,
			
			(0x0A ..= 0x0B, _, _) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x0C, _, _) => DeviceClass::Unrecognized { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x0D ..= 0x10, _, _) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x11, 0x00, 0x00) => Billboard(Known),
			(0x11, _, _) => Billboard(KnownOrUnrecognizedSubClassAndProtocol::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0x12, _, _) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0x13 ..= 0xDB, _, _) => DeviceClass::Unrecognized { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
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
			
			(0xDD ..= 0xDF, _, _) => DeviceClass::Unrecognized { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0xE0, 0x01, 0x00) => Bluetooth(BluetoothProtocol::UnrecognizedProtocol(0x00)),
			(0xE0, 0x01, 0x01) => Bluetooth(ProgrammingInterface),
			(0xE0, 0x01, 0x02) => Bluetooth(UwbRadioControlInterface),
			(0xE0, 0x01, 0x03) => Bluetooth(RemoteNdis),
			(0xE0, 0x01, 0x04) => Bluetooth(AmpController),
			(0xE0, 0x01, _) => Bluetooth(BluetoothProtocol::UnrecognizedProtocol(protocol_code)),
			(0xE0, _, _) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0xE1 ..= 0xEE, _, _) => DeviceClass::Unrecognized { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0xEF, 0x00, _) => DeviceClass::Miscellaneous(MiscellaneousDeviceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			(0xEF, 0x01, 0x00) => DeviceClass::Miscellaneous(Sync(SyncProtocol::UnrecognizedProtocol(0x00))),
			(0xEF, 0x01, 0x01) => DeviceClass::Miscellaneous(Sync(Active)),
			(0xEF, 0x01, 0x02) => DeviceClass::Miscellaneous(Sync(Palm)),
			(0xEF, 0x01, _) => DeviceClass::Miscellaneous(Sync(SyncProtocol::UnrecognizedProtocol(protocol_code))),
			(0xEF, 0x02, 0x00) => DeviceClass::Miscellaneous(Association(AssociationProtocol::UnrecognizedProtocol(0x00))),
			(0xEF, 0x02, 0x01) => DeviceClass::Miscellaneous(Association(InterfaceAssociationDescriptor)),
			(0xEF, 0x02, 0x02) => DeviceClass::Miscellaneous(Association(WireAdapterMultifunctionPeripheralProgrammingInterface)),
			(0xEF, 0x02, _) => DeviceClass::Miscellaneous(Association(AssociationProtocol::UnrecognizedProtocol(protocol_code))),
			(0xEF, 0x03, 0x00) => DeviceClass::Miscellaneous(MiscellaneousDeviceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			(0xEF, 0x03, 0x01) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			(0xEF, 0x03, _) => DeviceClass::Miscellaneous(MiscellaneousDeviceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			(0xEF, 0x04, 0x00) => DeviceClass::Miscellaneous(MiscellaneousDeviceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			(0xEF, 0x04, 0x01 ..= 0x07) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			(0xEF, 0x04, _) => DeviceClass::Miscellaneous(MiscellaneousDeviceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			(0xEF, 0x05, 0x00 ..= 0x02) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			(0xEF, 0x05, _) => DeviceClass::Miscellaneous(MiscellaneousDeviceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			(0xEF, 0x06, 0x00) => DeviceClass::Miscellaneous(StreamTransportEfficientProtocolForContentProtection(StreamTransportEfficientProtocol::UnrecognizedProtocol(0x00))),
			(0xEF, 0x06, 0x01) => DeviceClass::Miscellaneous(StreamTransportEfficientProtocolForContentProtection(Ordinary)),
			(0xEF, 0x06, 0x02) => DeviceClass::Miscellaneous(StreamTransportEfficientProtocolForContentProtection(Raw)),
			(0xEF, 0x06, _) => DeviceClass::Miscellaneous(StreamTransportEfficientProtocolForContentProtection(StreamTransportEfficientProtocol::UnrecognizedProtocol(protocol_code))),
			(0xEF, 0x07, 0x00) => DeviceClass::Miscellaneous(DvbCommonInterface(DvbCommonDeviceProtocol::UnrecognizedProtocol(0x00))),
			(0xEF, 0x07, 0x01) => DeviceClass::Miscellaneous(DvbCommonInterface(CommandInterface)),
			(0xEF, 0x07, 0x02) => DeviceClass::Miscellaneous(DvbCommonInterface(DvbCommonDeviceProtocol::UnrecognizedProtocol(protocol_code))),
			(0xEF, 0x07, _) => DeviceClass::Miscellaneous(DvbCommonInterface(DvbCommonDeviceProtocol::UnrecognizedProtocol(protocol_code))),
			(0xEF, _, _) => DeviceClass::Miscellaneous(MiscellaneousDeviceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code, protocol_code })),
			
			(0xF0 ..= 0xFD, _, _) => DeviceClass::Unrecognized { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0xFE, _, _) => ShouldBeInterfaceOnly { class_code, unrecognized_sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
			
			(0xFF, _, _) => VendorSpecific(UnrecognizedSubClass { sub_class_code, protocol_code }),
		}
	}
}
