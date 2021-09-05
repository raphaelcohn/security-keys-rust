// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB version 2.0 hub descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version2HubDescriptor
{
	logical_power_switching_mode: LogicalPowerSwitchingMode,
	
	is_part_of_a_compound_device: bool,
	
	overcurrent_protection_mode: OvercurrentProtectionMode,
	
	transaction_translator_think_time: TransactorTranslatorThinkTime,
	
	port_indicators_supported: bool,
	
	time_in_milliseconds_from_power_on_a_port_until_power_is_good_on_that_port: u16,
	
	maximum_current_requirement_in_milliamps: u8,
	
	downstream_ports: DownstreamPorts<Version2DownstreamPortSetting>,
}

impl HubDescriptorTrait for Version2HubDescriptor
{
	type DPS = Version2DownstreamPortSetting;
	
	#[inline(always)]
	fn logical_power_switching_mode(&self) -> LogicalPowerSwitchingMode
	{
		self.logical_power_switching_mode
	}
	
	#[inline(always)]
	fn is_part_of_a_compound_device(&self) -> bool
	{
		self.is_part_of_a_compound_device
	}
	
	#[inline(always)]
	fn overcurrent_protection_mode(&self) -> OvercurrentProtectionMode
	{
		self.overcurrent_protection_mode
	}
	
	#[inline(always)]
	fn time_in_milliseconds_from_power_on_a_port_until_power_is_good_on_that_port(&self) -> u16
	{
		self.time_in_milliseconds_from_power_on_a_port_until_power_is_good_on_that_port
	}
	
	#[inline(always)]
	fn downstream_ports(&self) -> &DownstreamPorts<Self::DPS>
	{
		&self.downstream_ports
	}
}

impl Version2HubDescriptor
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn transaction_translator_think_time(&self) -> TransactorTranslatorThinkTime
	{
		self.transaction_translator_think_time
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn port_indicators_supported(&self) -> bool
	{
		self.port_indicators_supported
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_current_requirement_in_milliamps(&self) -> u8
	{
		self.maximum_current_requirement_in_milliamps
	}
	
	const MinimumBLength: usize = 7;
	
	#[inline(always)]
	fn get_and_parse(device_connection: &DeviceConnection) -> Result<DeadOrAlive<Option<Self>>, Version2HubDescriptorParseError>
	{
		use Version2HubDescriptorParseError::*;
		
		let mut buffer: [MaybeUninit<u8>; 255] = MaybeUninit::uninit_array();
		let dead_or_alive = get_version_2_hub_device_descriptor(device_connection.device_handle_non_null(), &mut buffer).map_err(GetDescriptor)?;
		let descriptor_body = match return_ok_if_dead!(dead_or_alive)
		{
			None => return Ok(Alive(None)),
			
			Some(descriptor_bytes) => descriptor_bytes,
		};
		
		if unlikely!((DescriptorHeaderLength + descriptor_body.len()) < Self::MinimumBLength)
		{
			return Err(HubDescriptorTooShort)
		}
		
		let hub_characteristics = descriptor_body.u16(descriptor_index::<3>());
	
		Ok
		(
			Alive
			(
				Some
				(
					Self
					{
						logical_power_switching_mode: unsafe { transmute((hub_characteristics & 0b0000_0011) as u8) },
						
						is_part_of_a_compound_device: (hub_characteristics & 0b0000_0100) != 0,
						
						overcurrent_protection_mode: unsafe { transmute(((hub_characteristics & 0b0001_1000) as u8) >> 3) },
						
						transaction_translator_think_time: unsafe { transmute(((hub_characteristics & 0b0110_0000) as u8) >> 5) },
						
						port_indicators_supported: (hub_characteristics & 0b1000_0000) != 0,
						
						time_in_milliseconds_from_power_on_a_port_until_power_is_good_on_that_port: (descriptor_body.u8(descriptor_index::<5>()) as u16) * 2,
						
						maximum_current_requirement_in_milliamps: descriptor_body.u8(descriptor_index::<6>()),
						
						downstream_ports: Self::downstream_ports_parse(descriptor_body)?,
					}
				)
			)
		)
	}
	
	#[inline(always)]
	fn downstream_ports_parse(descriptor_body: &[u8]) -> Result<DownstreamPorts<Version2DownstreamPortSetting>, Version2HubDescriptorParseError>
	{
		use Version2HubDescriptorParseError::*;
		
		let number_of_downstream_ports =
		{
			let bNbrPorts = descriptor_body.u8(descriptor_index::<2>());
			if unlikely!(bNbrPorts == 255)
			{
				return Err(MoreThan254Ports)
			}
			bNbrPorts as usize
		};
		
		let mut port_settings = Vec::new_with_capacity(number_of_downstream_ports).map_err(CouldNotAllocatePortsSettings)?;
		
		let remaining_bytes_of_descriptor = descriptor_body.get_unchecked_range_safe(Version2HubDescriptor::MinimumBLength .. );
		
		let length = remaining_bytes_of_descriptor.len();
		if length == 0
		{
			for _ in 0 .. number_of_downstream_ports
			{
				port_settings.push_unchecked
				(
					Version2DownstreamPortSetting
					{
						device_is_removable: true,
						
						usb_1_0_power_control: true,
					}
				)
			}
			return Ok(DownstreamPorts(port_settings))
		}
		
		let number_of_bytes_required_for_number_of_downstream_ports = Self::number_of_downstream_ports_to_number_of_bytes(number_of_downstream_ports);
		
		let number_of_device_removable_bytes = number_of_bytes_required_for_number_of_downstream_ports;
		let number_of_power_control_bytes = number_of_bytes_required_for_number_of_downstream_ports;
		
		let total_number_of_bytes = number_of_device_removable_bytes + number_of_power_control_bytes;
		if unlikely!(length < total_number_of_bytes)
		{
			eprintln!("descriptor_body original len {}", descriptor_body.len());
			eprintln!("length {}", length);
			eprintln!("number_of_downstream_ports {}", number_of_downstream_ports);
			eprintln!("remaining_bytes_of_descriptor {:?}", remaining_bytes_of_descriptor);
			return Err(TooFewVariableBytes { number_of_downstream_ports, length, number_of_bytes_required_for_number_of_downstream_ports })
		}
		
		for port_number in 1 ..= number_of_downstream_ports
		{
			port_settings.push_unchecked
			(
				Version2DownstreamPortSetting
				{
					device_is_removable: Self::extract_bit(remaining_bytes_of_descriptor, port_number, 0, 0) == 0,
					
					usb_1_0_power_control: Self::extract_bit(remaining_bytes_of_descriptor, port_number, 1, number_of_bytes_required_for_number_of_downstream_ports) != 0,
				}
			)
		}
		Ok(DownstreamPorts(port_settings))
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
	const fn number_of_downstream_ports_to_number_of_bytes(number_of_downstream_ports: usize) -> usize
	{
		const ReservedBit: usize = 1;
		let number_of_bits = ReservedBit + number_of_downstream_ports;
		(number_of_bits + (Self::BitsPerByte - 1)) / Self::BitsPerByte
	}
}
