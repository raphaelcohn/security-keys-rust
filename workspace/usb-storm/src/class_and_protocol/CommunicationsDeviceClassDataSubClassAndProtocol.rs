// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Communications device class data sub class.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum CommunicationsDeviceClassDataSubClassAndProtocol
{
	#[allow(missing_docs)]
	NoSpecificProtocolRequired,
	
	/// USB Device Class specification for Network Control Block.
	NetworkTransferBlock,
	
	/// USB Device Class specification for Mobile Broadband Interface Model.
	///
	/// 'IP + DSS'.
	NetworkTransferBlockMobileBroadbandInterfaceModel,
	
	#[allow(missing_docs)]
	Reserved
	{
		protocol_code: u8,
	},
	
	/// I.430: Physical interface protocol for ISDN BRI.
	IsdnBri,
	
	/// ISO/IEC 3309-1993.
	///
	/// High-Level Data Link Control (HDLC).
	HighLevelDataLinkControl,
	
	#[allow(missing_docs)]
	Transparent,
	
	/// Management protocol for Q.921 data link protocol (Q.921M).
	ManagementProtocolForQ921DataLinkProtocol,
	
	/// Q.921 data link protocol.
	DataLinkProtocolForQ921,
	
	/// TEI-multiplextor for Q.921 data link protocol.
	TeiMultiplexorForQ921DataLinkProtocol,
	
	/// V.42bis data compression procedures.
	V42bis,
	
	/// Q.831 Euro-ISDN.
	EuroIsdnProtocolControl,
	
	/// V.24 rate adaptation to ISDN (V.120).
	V120,
	
	/// CAPI 2.0.
	Capi2,
	
	#[allow(missing_docs)]
	HostBasedDriver,
	
	#[allow(missing_docs)]
	UseProtocolUnitFunctionalDescriptorsOnCommunicationsClassInterface,
	
	#[allow(missing_docs)]
	VendorSpecific,
	
	#[allow(missing_docs)]
	Unrecognized(UnrecognizedSubClass),
}
