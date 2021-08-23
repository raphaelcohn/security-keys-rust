// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Mass storage sub class.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum MassStorageSubClass
{
	#[allow(missing_docs)]
	ScsiCommandSetNotReported(MassStorageProtocol),
	
	/// Reduced Block Commands (RBC) INCITS 330:2000 (see <https://www.t10.org>).
	ReducedBlockCommands(MassStorageProtocol),
	
	/// Multi-Media Command Set 5 (MMC-5) T10/1675-D (see <https://www.t10.org>).
	MultiMediaCommandSet5(MassStorageProtocol),
	
	/// QIC-157; obsolete.
	Qic_157(MassStorageProtocol),
	
	/// Specifies how to interface floppy disk drives.
	UFI(MassStorageProtocol),
	
	/// SFF-8070i obsolete.
	Sff_8070i(MassStorageProtocol),
	
	#[allow(missing_docs)]
	ScsiTransparentCommandSet(MassStorageProtocol),
	
	/// Lockable Storage Devices Feature Specification (LSDFS); sometimes abbreviated LSD FS.
	LockableStorageDevicesFeatureSpecification(MassStorageProtocol),
	
	/// IEEE 1667 (Standard Protocol for Authentication in Host Attachments of Transient Storage Devices).
	Ieee1667(MassStorageProtocol),
	
	#[allow(missing_docs)]
	VendorSpecific(MassStorageProtocol),
	
	/// Unrecognized.
	Unrecognized(UnrecognizedSubClass),
}
