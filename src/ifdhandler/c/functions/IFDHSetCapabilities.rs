// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// This function should set the slot or card capabilities for a particular slot or card.
	/// If you have only 1 card slot and don't mind loading a new driver for each reader then ignore `Lun`.
	///
	///
	/// * `Lun`: Logical Unit Number.
	/// * `Tag`: Tag of the desired data value,
	/// * `Length`: Length of the desired data value.
	/// * `Value`: Value of the desired data.
	///
	/// ## Tag values
	///
	/// These overlap with PC/SC attribute definitions.
	/// There are not explicitly defined `TAG_IFD_*` values that are general across drivers.
	///
	///
	/// ## Addtional Tag Values supportd by ifd-ccid.bundle (CCID)
	///
	/// The ifd-ccid driver does not support any tags at all, and returns `IFD_NOT_SUPPORTED` (in violation of the documented behaviour) unless the `Lun` is invalid, in which case, it returns `IFD_COMMUNICATION_ERROR`.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: NOT DOCUMENTED, but used in practice for an invalid Lun.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ERROR_TAG`: Invalid (?unsupported) tag given.
	/// * `IFD_ERROR_SET_FAILURE`: Could not set value.
	/// * `IFD_ERROR_VALUE_READ_ONLY`: Trying to set a read only value.
	/// * `IFD_NOT_SUPPORTED`:  NOT DOCUMENTED, but used in practice.
	pub(in crate::ifdhandler) fn IFDHSetCapabilities(Lun: DWORD, Tag: DWORD, Length: DWORD, Value: *mut u8) -> RESPONSECODE;
}
