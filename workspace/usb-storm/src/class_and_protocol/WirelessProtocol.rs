// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// AT (modem) commands.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum WirelessProtocol
{
	/// PCCA STD-101, Data Transmission Systems and Equipment - Serial Asynchronous Automatic Dialing and Control for Character Mode DCE on Wireless Data Services, Portable Computer and Communications Association.
	PCCA_101,
	
	/// PCCA STD-101 and Annex O (Commands for Wakeup control).
	PCCA_101_and_Annex_O,
	
	/// ETSI GTS GSM 07.07 V5.0.0 (1996-07) Digital cellular telecommunications system (Phase 2+); AT command set for GSM Mobile Equipment (ME) (GSM 07.07), ETSI.
	GSM_07_07,
	
	/// AT command set for User Equipment (UE), 3rd Generation Partnership Project; Technical Specification Group Terminals, Document 27.007,Version 3.9.0 (June 2001).
	_3GPP_27_007,
	
	/// 3GPP2 TSG.C Specification C-S0017-0.
	///
	/// Specifies AT command sets to be used for cmda2000 mobile terminals.
	/// Code Division Multiple Access (CDMA).
	TIA_for_CDMA_C_S0017_0,
	
	#[allow(missing_docs)]
	VendorSpecific,
	
	/// Commands defined by Command Set Functional Descriptor.
	ExternalProtocol,
	
	#[allow(missing_docs)]
	Unrecognized
	{
		protocol_code: u8,
	},
}
