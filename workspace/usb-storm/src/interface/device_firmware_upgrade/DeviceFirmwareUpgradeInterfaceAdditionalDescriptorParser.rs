// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(super) struct DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParser;

impl AdditionalDescriptorParser for DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParser
{
	type Descriptor = DeviceFirmwareUpgradeInterfaceAdditionalDescriptor;
	
	type Error = DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<(Self::Descriptor, usize)>, Self::Error>
	{
		use DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParseError::*;
		
		match descriptor_type
		{
			0x21 => (),
			
			_ => return Err(DescriptorIsNeitherOfficialOrVendorSpecific(descriptor_type)),
		};
		
		// On my Apple Mac Pro trashcan, this USB descriptor omits the trailing `bcdDFUVersion` field and so has a short bLength.
		const SizeOfVersionField: u8 = size_of::<u16>() as u8;
		const MinimumBLength: u8 = 7;
		const CorrectBLength: u8 = MinimumBLength + SizeOfVersionField;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParseError, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let bmAttributes = descriptor_body.u8_adjusted::<2>();
		if unlikely!(bmAttributes & 0b1111_0000 != 0)
		{
			return Err(ReservedAttributesBits4To7 { bmAttributes })
		}
		let will_detach = (bmAttributes & 0b0000_1000) != 0;
		let manifestation_tolerant = (bmAttributes & 0b0000_0100) != 0;
		let can_upload = (bmAttributes & 0b0000_0010) != 0;
		let can_download = (bmAttributes & 0b0000_0001) != 0;
		let maximum_detach_time_out_milliseconds = descriptor_body.u16_adjusted::<3>();
		let maximum_number_of_bytes_per_control_write_transaction = descriptor_body.u16_adjusted::<5>();
		
		const CorrectDescriptorBodyLength: usize = reduce_b_length_to_descriptor_body_length(CorrectBLength);
		let version = if descriptor_body_length >= CorrectDescriptorBodyLength
		{
			Some(descriptor_body.version_adjusted::<7>().map_err(Version)?)
		}
		else
		{
			None
		};
		
		Ok
		(
			Some
			(
				(
					DeviceFirmwareUpgradeInterfaceAdditionalDescriptor
					{
						will_detach,
						
						manifestation_tolerant,
						
						can_upload,
						
						can_download,
						
						maximum_detach_time_out_milliseconds,
						
						maximum_number_of_bytes_per_control_write_transaction,
						
						version,
					},
					descriptor_body_length,
				)
			)
		)
	}
}
