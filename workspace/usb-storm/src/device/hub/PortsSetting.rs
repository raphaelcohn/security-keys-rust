// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Ports setting.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortsSetting<PS: PortSetting>(Vec<PS>);

impl<PS: PortSetting> PortsSetting<PS>
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn setting(&self, port_number: PortNumber) -> PS
	{
		debug_assert!(port_number.get() <= self.number_of_ports());
		self.0.get_unchecked_value_safe(port_number.get() - 1)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn number_of_ports(&self) -> u8
	{
		self.0.len() as u8
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn maximum_port_number(&self) -> Option<NonZeroU8>
	{
		NonZeroU8::new(self.number_of_ports())
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn iterate(&self) -> impl Iterator<Item=(PortNumber, PS)> + '_
	{
		self.0.iter().enumerate().map(|(index, port_setting)| (new_non_zero_u8((index as u8) + 1), *port_setting))
	}
}

impl PortsSetting<Version3PortSetting>
{
	#[inline(always)]
	fn version_3_parse(descriptor_body: &[u8]) -> Result<Self, Version3HubDescriptorParseError>
	{
		use Version3HubDescriptorParseError::*;
		
		let number_of_downstream_ports =
		{
			let bNbrPorts = descriptor_body.u8(descriptor_index::<2>());
			if unlikely!(bNbrPorts > 15)
			{
				return Err(TooManyPorts { bNbrPorts })
			}
			bNbrPorts as usize
		};
		
		let device_removable = descriptor_body.u16(descriptor_index::<10>()) as usize;
		
		let mut port_settings = Vec::new_with_capacity(number_of_downstream_ports).map_err(CouldNotAllocatePortsSettings)?;
		for port_number in 1 ..= number_of_downstream_ports
		{
			port_settings.push_unchecked
			(
				Version3PortSetting
				{
					device_is_removable: ((device_removable >> port_number) & 0b1) != 0,
				}
			)
		}
		Ok(Self(port_settings))
	}
}

impl PortsSetting<Version2PortSetting>
{
	#[inline(always)]
	fn version_2_parse(descriptor_body: &[u8]) -> Result<Self, Version2HubDescriptorParseError>
	{
		use Version2HubDescriptorParseError::*;
		
		let number_of_downstream_ports =
		{
			let bNbrPorts = descriptor_body.u8(descriptor_index::<2>());
			if unlikely!(bNbrPorts == 255)
			{
				return Err(WhilstUsb2PermitsAValueOf255HereWeUseANonZeroU8ForPortNumber)
			}
			bNbrPorts as usize
		};
		
		const ReservedBit: usize = 1;
		let number_of_device_removable_bytes = Self::number_of_bits_to_number_of_bytes(ReservedBit + number_of_downstream_ports);
		let number_of_power_control_bytes = Self::number_of_bits_to_number_of_bytes(number_of_downstream_ports);
		
		let remaining_bytes_of_descriptor = descriptor_body.get_unchecked_range_safe(Version2HubDescriptor::MinimumBLength .. );
		
		let total_number_of_bytes = number_of_device_removable_bytes + number_of_power_control_bytes;
		if unlikely!(remaining_bytes_of_descriptor.len() < total_number_of_bytes)
		{
			return Err(TooFewVariableBytes)
		}
		
		let mut port_settings = Vec::new_with_capacity(number_of_downstream_ports).map_err(CouldNotAllocatePortsSettings)?;
		for port_number in 1 ..= number_of_downstream_ports
		{
			port_settings.push_unchecked
			(
				Version2PortSetting
				{
					device_is_removable: Self::extract_bit(remaining_bytes_of_descriptor, port_number, 0, 0) == 0,
					
					usb_1_0_power_control: Self::extract_bit(remaining_bytes_of_descriptor, port_number, 1, number_of_device_removable_bytes) != 0,
				}
			)
		}
		Ok(Self(port_settings))
	}
	
	const BitsPerByte: usize = 8;
	
	#[inline(always)]
	fn extract_bit(remaining_bytes_of_descriptor: &[u8], number: usize, correction: usize, offset: usize) -> u8
	{
		let bit_index = (number - correction) * Self::BitsPerByte;
		let byte_index = bit_index / Self::BitsPerByte;
		let relative_bit_index = (bit_index % Self::BitsPerByte) as u8;
		let device_is_removable_byte = remaining_bytes_of_descriptor.u8(offset + byte_index);
		device_is_removable_byte & (1 << relative_bit_index)
	}
	
	#[inline(always)]
	const fn number_of_bits_to_number_of_bytes(number_of_bits: usize) -> usize
	{
		(number_of_bits + Self::BitsPerByte - 1) / Self::BitsPerByte
	}
}
