// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(in crate::ifdhandle) struct LogicalUnitNumber
{
	/// Confusingly also called `slot_index` in PCSC.
	device_index: u16,

	/// Card readers have card slots; all card readers have at least one slot.
	///
	/// In USB terms, the maximum value is `bMaxSlotIndex` except for the following composite devices which have special treatment:-
	///
	/// * Which have two slots:-
	/// 	* GEMALTOPROXDU (Vendor Identifier 0x08E6, Product Identifier 0x5503).
	/// 	* GEMALTOPROXSU (Vendor Identifier 0x08E6, Product Identifier 0x5504).
	/// 	* HID_OMNIKEY_5422 (Vendor Identifier 0x076B, Product Identifier 0x5422).
	/// * Which have four slots:-
	/// 	* FEITIANR502DUAL (Vendor 0x096E, Product Identifier: 0x060D).
	zero_based_card_slot: u16,
}

impl LogicalUnitNumber
{
	const UsedAsUnassigned: Self = Self
	{
		device_index: 0xFFFF,
		
		zero_based_card_slot: 0xFFFF,
	};
	
	#[inline(always)]
	const fn from_device_index_for_one_card_reader_slot(device_index: u16) -> Self
	{
		Self
		{
			device_index,
		
			zero_based_card_slot: 0,
		}
	}
	
	#[inline(always)]
	const fn into_DWORD(self) -> DWORD
	{
		let value = ((self.device_index as u32) << 16) | (self.zero_based_card_slot as u32);
		value as DWORD
	}
}
