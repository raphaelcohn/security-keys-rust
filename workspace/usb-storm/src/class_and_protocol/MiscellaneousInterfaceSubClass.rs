// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Miscellaneous interface sub class.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum MiscellaneousInterfaceSubClass
{
	#[allow(missing_docs)]
	Sync(SyncProtocol),
	
	#[allow(missing_docs)]
	CableBasedAssociationFramework
	{
		unrecognized_protocol: Option<u8>,
	},
	
	#[allow(missing_docs)]
	RemoteNetworkDriverInterfaceSpecificationProtocol(RemoteNetworkDriverInterfaceSpecificationProtocol),
	
	#[allow(missing_docs)]
	Usb3Vision(Usb3VisionControlProtocol),
	
	#[allow(missing_docs)]
	StreamTransportEfficientProtocolForContentProtection(StreamTransportEfficientProtocol),
	
	#[allow(missing_docs)]
	DvbCommonInterface(DvbCommonInterfaceProtocol),
	
	#[allow(missing_docs)]
	Unrecognized(UnrecognizedSubClass),
}
