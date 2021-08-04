// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use libusb1_sys::libusb_device_descriptor;
use libusb1_sys::libusb_interface_descriptor;
use serde::Deserialize;
use serde::Serialize;
use std::num::NonZeroU8;
use swiss_army_knife::non_zero::new_non_zero_u8;


include!("ApplicationSpecificInterfaceSubClass.rs");
include!("AssociationProtocol.rs");
include!("AudioProtocol.rs");
include!("AudioSubClass.rs");
include!("AudioVideoInterfaceSubClass.rs");
include!("BluetoothProtocol.rs");
include!("DeviceClass.rs");
include!("DiagnosticProtocol.rs");
include!("DvbCommonDeviceProtocol.rs");
include!("DvbCommonInterfaceProtocol.rs");
include!("DiagnosticSubClass.rs");
include!("DebugDiagnosticProtocol.rs");
include!("HumanInterfaceDeviceInterfaceBootProtocol.rs");
include!("HumanInterfaceDeviceInterfaceSubClass.rs");
include!("InterfaceClass.rs");
include!("KnownOrUnrecognizedProtocol.rs");
include!("KnownOrUnrecognizedSubClassAndProtocol.rs");
include!("MiscellaneousDeviceSubClass.rs");
include!("MiscellaneousInterfaceSubClass.rs");
include!("RemoteNetworkDriverInterfaceSpecificationProtocol.rs");
include!("SmartCardInterfaceSubClass.rs");
include!("SmartCardProtocol.rs");
include!("StreamTransportEfficientProtocol.rs");
include!("SyncProtocol.rs");
include!("TestAndMeasurementProtocol.rs");
include!("TraceOverGeneralPurposeEndPointOnDvCDiagnosticProtocol.rs");
include!("UnrecognizedSubClass.rs");
include!("Usb3VisionControlProtocol.rs");
include!("VideoSubClass.rs");
include!("WireAdapterProtocol.rs");
include!("WirelessControllerSubClass.rs");
