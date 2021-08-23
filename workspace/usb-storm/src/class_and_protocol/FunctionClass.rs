// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Function class code.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum FunctionClass
{
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass01h>.
	Audio(AudioFunctionSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass02h>.
	CommunicationsDeviceClassControl(CommunicationsDeviceClassControlSubClass),
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass0Eh>.
	VideoInterfaceCollection,
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassFFh>.
	VendorSpecific(UnrecognizedSubClass),
	
	#[allow(missing_docs)]
	Unrecognized
	{
		class_code: u8,
		
		#[serde(flatten)]
		sub_class: UnrecognizedSubClass,
	},
}

impl FunctionClass
{
	#[allow(unused_qualifications)]
	#[inline(always)]
	pub(crate) fn parse(bFunctionClass: u8, bFunctionSubClass: u8, bFunctionProtocol: u8) -> Result<Self, FunctionClassParseError>
	{
		use AudioFunctionSubClass::*;
		use BasicAudioDeviceDefinition::*;
		use FunctionClass::*;
		use CommunicationsDeviceClassControlSubClass::*;
		use PublicSwitchedTelephoneNetworkProtocol::*;
		use Version3AudioFunctionSubClass::*;
		use WirelessProtocol::*;
		
		let class_code = bFunctionClass;
		let sub_class_code = bFunctionSubClass;
		let protocol_code = bFunctionProtocol;
		
		let this = match (class_code, sub_class_code, protocol_code)
		{
			(0x00, _, _) => return Err(FunctionClassParseError::ClassCodeCanNotBeZero),
			
			(0x01, 0x00, 0x20) => Audio(Version_2_0(Version2AudioFunctionSubClass::Undefined)),
			(0x01, _, 0x20) => Audio(Version_2_0(Version2AudioFunctionSubClass::Unrecognized { sub_class_code })),
			
			(0x01, 0x00, 0x30) => Audio(Version_3_0(Version3AudioFunctionSubClass::Undefined)),
			(0x01, 0x01, 0x30) => Audio(Version_3_0(Full_Version_3_0)),
			(0x01, 0x02 ..= 0x1F, 0x30) => Audio(Version_3_0(UnrecognizedButMightBeFull { sub_class_code })),
			(0x01, 0x20, 0x30) => Audio(Version_3_0(BasicAudio(GenericInputOutput))),
			(0x01, 0x21, 0x30) => Audio(Version_3_0(BasicAudio(Headphone))),
			(0x01, 0x22, 0x30) => Audio(Version_3_0(BasicAudio(Speaker))),
			(0x01, 0x23, 0x30) => Audio(Version_3_0(BasicAudio(Microphone))),
			(0x01, 0x24, 0x30) => Audio(Version_3_0(BasicAudio(Headset))),
			(0x01, 0x25, 0x30) => Audio(Version_3_0(BasicAudio(HeadsetAdapater))),
			(0x01, 0x26, 0x30) => Audio(Version_3_0(BasicAudio(Speakerphone))),
			(0x01, _, 0x30) => Audio(Version_3_0(BasicAudio(UnrecognizedBasicAudioDeviceDefinition { sub_class_code }))),
			
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
			
			(0x0E, 0x03, 0x00) => VideoInterfaceCollection,
			
			(0xFF, _, _) => FunctionClass::VendorSpecific(UnrecognizedSubClass { sub_class_code, protocol_code }),
			
			_ => FunctionClass::Unrecognized { class_code, sub_class: UnrecognizedSubClass { sub_class_code, protocol_code } },
		};
		
		Ok(this)
	}
}
