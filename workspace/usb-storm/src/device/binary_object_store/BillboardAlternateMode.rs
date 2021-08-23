// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Billboard alternate mode.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BillboardAlternateMode
{
	standard_or_vendor_identifier: u16,
	
	alternate_or_usb4_mode: u8,
	
	configuration_result: BillboardAlternateModeConfigurationResult,
	
	description: Option<LocalizedStrings>,
}

impl BillboardAlternateMode
{
	/// 0xFF00 for USB 4 devices.
	#[inline(always)]
	pub const fn standard_or_vendor_identifier(&self) -> u16
	{
		self.standard_or_vendor_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn alternate_or_usb4_mode(&self) -> u8
	{
		self.alternate_or_usb4_mode
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn configuration_result(&self) -> BillboardAlternateModeConfigurationResult
	{
		self.configuration_result
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[inline(always)]
	fn parse_alternate_modes(alternate_modes_bytes: &[u8], number_of_alternate_modes: usize, configuration_result: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Vec<Self>>, BillboardDeviceCapabilityParseError>
	{
		use BillboardDeviceCapabilityParseError::*;
		
		let mut alternate_modes = Vec::new_with_capacity(number_of_alternate_modes).map_err(CouldNotAllocateMemoryForModes)?;
		for index in 0 ..number_of_alternate_modes
		{
			alternate_modes.push_unchecked(return_ok_if_dead!(Self::parse(index, alternate_modes_bytes, configuration_result, string_finder)?));
		}
		
		Ok(Alive(alternate_modes))
	}
	
	#[inline(always)]
	fn parse(index: usize, alternate_modes_bytes: &[u8], configuration_result: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, BillboardDeviceCapabilityParseError>
	{
		Ok
		(
			Alive
			(
				Self
				{
					standard_or_vendor_identifier: alternate_modes_bytes.u16(0),
					
					alternate_or_usb4_mode: alternate_modes_bytes.u8(1),
					
					configuration_result: BillboardAlternateModeConfigurationResult::parse(index, configuration_result),
					
					description:
					{
						let description = string_finder.find_string(alternate_modes_bytes.u8(2)).map_err(|cause| BillboardDeviceCapabilityParseError::InvalidAlternateModeDescription { cause, index })?;
						return_ok_if_dead!(description)
					},
				}
			)
		)
	}
	
	#[inline(always)]
	fn parse_number_of_alternate_modes(device_capability_bytes: &[u8]) -> Result<usize, BillboardDeviceCapabilityParseError>
	{
		use BillboardDeviceCapabilityParseError::*;
		
		const BytesPerMode: usize = 4;
		
		let number_of_alternate_modes =
		{
			let number_of_alternate_modes = device_capability_bytes.u8(capability_descriptor_index::<4>());
			if unlikely!(number_of_alternate_modes > Self::MAX_NUM_ALT_OR_USB4_MODE)
			{
				return Err(TooManyModes { number_of_modes: number_of_alternate_modes })
			}
			number_of_alternate_modes as usize
		};
		let minimum_b_length = BillboardDeviceCapability::MinimumBLength + (number_of_alternate_modes * BytesPerMode);
		let acutal_b_length = device_capability_bytes.len() + DeviceCapability::DeviceCapabilityHeaderSize;
		if acutal_b_length < minimum_b_length
		{
			return Err(TooShort)
		}
		
		Ok(number_of_alternate_modes)
	}
	
	const MAX_NUM_ALT_OR_USB4_MODE: u8 = 0x34;
}
