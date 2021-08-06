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
		
		let length = Self::reduce_b_length_to_descriptor_body_length(bLength);
		let descriptor_bytes = remaining_bytes.get_unchecked_range_safe(.. length);
		
		let length = descriptor_bytes.len();
		const MinimumLength: usize = 5;
		if unlikely!(length < MinimumLength)
		{
			return Err(WrongLength { length })
		}
		
		let bmAttributes = descriptor_bytes.u8::<2>();
		
		if unlikely!(bmAttributes & 0b1111_0000 != 0)
		{
			return Err(ReservedAttributesBits4To7 { bmAttributes })
		}
		
		let will_detach = (bmAttributes & 0b0000_1000) != 0;
		let manifestation_tolerant = (bmAttributes & 0b0000_0100) != 0;
		let can_upload = (bmAttributes & 0b0000_0010) != 0;
		let can_download = (bmAttributes & 0b0000_0001) != 0;
		let maximum_detach_time_out_milliseconds = descriptor_bytes.u16::<3>();
		let maximum_number_of_bytes_per_control_write_transaction = descriptor_bytes.u16::<5>();
		
		const StandardLength: usize = 7;
		let version = if length >= StandardLength
		{
			Some(descriptor_bytes.version::<7>().map_err(Version)?)
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
					
					length,
				)
			)
		)
	}
}
