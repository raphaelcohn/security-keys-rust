// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// This trait represents device capabilities that can only be discovered using `IFDHGetCapabilities()` with a `Lun`, yet are nothing to do with either a device or a slot.
///
/// However, they are logically linked to a driver.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub(in crate::ifdhandler) struct FixedUsbDeviceCapabilities
{
	/// PC/SC's ifd-ccid driver models composite devices as if they have multiple slots.
	///
	/// The following devices are known to be composite:-
	///
	/// * GEMALTOPROXDU (Vendor Identifier 0x08E6, Product Identifier 0x5503).
	/// * GEMALTOPROXSU (Vendor Identifier 0x08E6, Product Identifier 0x5504).
	/// * HID_OMNIKEY_5422 (Vendor Identifier 0x076B, Product Identifier 0x5422).
	/// * FEITIANR502DUAL (Vendor 0x096E, Product Identifier: 0x060D).
	///
	/// This list was taken from:-
	///
	/// `src/ifdhandler.c`, function `IFDHGetCapabilities()` (list defined as if ladder guarded by #define `USE_COMPOSITE_AS_MULTISLOT`).
	/// `src/ccid_usb.c`, function `OpenUSBByName()` (list defined as if ladder guarded by #define `USE_COMPOSITE_AS_MULTISLOT`; if ladder repeated twice in function).
	///
	/// These composite devices have two slots:-
	///
	/// * GEMALTOPROXDU (Vendor Identifier 0x08E6, Product Identifier 0x5503).
	/// * GEMALTOPROXSU (Vendor Identifier 0x08E6, Product Identifier 0x5504).
	/// * HID_OMNIKEY_5422 (Vendor Identifier 0x076B, Product Identifier 0x5422).
	///
	/// These composite devices have four slots:-
	///
	/// * FEITIANR502DUAL (Vendor 0x096E, Product Identifier: 0x060D).
	composite_maximum_number_of_slots: Option<NonZeroU8>,
}

impl FixedUsbDeviceCapabilities
{
	#[inline(always)]
	pub(in crate::ifdhandler) const fn new(composite_maximum_number_of_slots: Option<NonZeroU8>) -> FixedUsbDeviceCapabilities
	{
		Self
		{
			composite_maximum_number_of_slots
		}
	}
	
	/// This is the number of slots (USB descriptor value `bMaxSlotIndex + 1`) except for a small number of composite card readers.
	///
	/// In practice, this value has not been observed to exceed 8 either non-composite or composite card readers.
	#[inline(always)]
	pub(in crate::ifdhandler) fn TAG_IFD_SLOTS_NUMBER(&self, maximum_slot_index: u8) -> NonZeroU8
	{
		match self.composite_maximum_number_of_slots
		{
			None => new_non_zero_u8(maximum_slot_index + 1),
			
			Some(composite_maximum_number_of_slots) => composite_maximum_number_of_slots
		}
	}
}
