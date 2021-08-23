// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Communications device class control sub class.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum CommunicationsDeviceClassControlSubClass
{
	#[allow(missing_docs)]
	Reserved0x00
	{
		protocol_code: u8,
	},
	
	/// USB CDC Subclass Specification for PSTN Devices.
	DirectLineControlModel(PublicSwitchedTelephoneNetworkProtocol),
	
	/// USB CDC Subclass Specification for PSTN Devices.
	AbstractControlModel(PublicSwitchedTelephoneNetworkProtocol),
	
	/// USB CDC Subclass Specification for PSTN Devices.
	TelephoneControlModel(PublicSwitchedTelephoneNetworkProtocol),
	
	/// USB CDC Subclass Specification for ISDN Devices.
	MultiChannelControlModel(KnownVendorSpecificOrUnrecognizedProtocol),
	
	/// USB CDC Subclass Specification for ISDN Devices.
	///
	/// 'CAPI'.
	CapiControlModel(KnownVendorSpecificOrUnrecognizedProtocol),
	
	/// USB CDC Subclass Specification for Ethernet Devices.
	EthernetControlModel(KnownVendorSpecificOrUnrecognizedProtocol),
	
	/// USB CDC Subclass Specification for ATM Devices.
	AsynchronousTransferModeControlModel(KnownVendorSpecificOrUnrecognizedProtocol),
	
	/// USB CDC Subclass Specification for Wireless Mobile Communications Devices.
	WirelessHandsetControlModel(WirelessProtocol),
	
	/// USB CDC Subclass Specification for Wireless Mobile Communications Devices.
	DeviceManagementModel(WirelessProtocol),
	
	/// USB CDC Subclass Specification for Wireless Mobile Communications Devices.
	MobileDirectLineModel(WirelessProtocol),
	
	/// USB CDC Subclass Specification for Wireless Mobile Communications Devices.
	///
	/// [OBEX](https://en.wikipedia.org/wiki/OBject_EXchange).
	OBjectEXchange(WirelessProtocol),
	
	/// USB CDC Subclass Specification for Ethernet Emulation Devices.
	EthernetEmulationModel(KnownVendorSpecificOrUnrecognizedProtocol),
	
	/// USB CDC Subclass Specification for Subclass Specifications for Network Control Model Devices.
	NetworkControlModel(KnownVendorSpecificOrUnrecognizedProtocol),
	
	/// USB CDC Subclass Specification for Subclass Specifications for Mobile Broadband Interface Model.
	MobileBroadbandInterfaceModel(KnownVendorSpecificOrUnrecognizedProtocol),
	
	#[allow(missing_docs)]
	ReservedFutureUse
	{
		/// From 0x0D to 0x7F inclusive.
		sub_class_code: u8,
		
		protocol_code: u8,
	},
	
	#[allow(missing_docs)]
	VendorSpecific
	{
		/// From 0x80 to 0xFF inclusive.
		sub_class_code: u8,
		
		protocol_code: u8,
	},
	
}
