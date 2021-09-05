// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB version 2.0 hub descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version3HubDescriptor
{
	logical_power_switching_mode: LogicalPowerSwitchingMode,
	
	is_part_of_a_compound_device: bool,
	
	overcurrent_protection_mode: OvercurrentProtectionMode,
	
	time_in_milliseconds_from_power_on_a_port_until_power_is_good_on_that_port: u16,
	
	maximum_current_requirement_scalar: u8,
	
	packet_header_decode_latency: PacketHeaderDecodeLatency,
	
	maximum_delay_in_nanoseconds: u16,
	
	downstream_ports: DownstreamPorts<Version3DownstreamPortSetting>,
}

impl HubDescriptorTrait for Version3HubDescriptor
{
	type DPS = Version3DownstreamPortSetting;
	
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
	
	/// Maximum value is 510.
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

impl Version3HubDescriptor
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_current_requirement_scalar(&self) -> u8
	{
		self.maximum_current_requirement_scalar
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn packet_header_decode_latency(&self) -> PacketHeaderDecodeLatency
	{
		self.packet_header_decode_latency
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_delay_in_nanoseconds(&self) -> u16
	{
		self.maximum_delay_in_nanoseconds
	}
	
	#[inline(always)]
	fn get_and_parse(device_connection: &DeviceConnection) -> Result<DeadOrAlive<Option<Self>>, Version3HubDescriptorParseError>
	{
		use Version3HubDescriptorParseError::*;
		
		let mut buffer: [MaybeUninit<u8>; 255] = MaybeUninit::uninit_array();
		let dead_or_alive = get_version_3_hub_device_descriptor(device_connection.device_handle_non_null(), &mut buffer).map_err(GetDescriptor)?;
		let descriptor_body = match return_ok_if_dead!(dead_or_alive)
		{
			None => return Ok(Alive(None)),
			
			Some(descriptor_bytes) => descriptor_bytes,
		};
		
		{
			const BLength: usize = 12;
			if unlikely!((DescriptorHeaderLength + descriptor_body.len()) < BLength)
			{
				return Err(HubDescriptorTooShort)
			}
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
						
						time_in_milliseconds_from_power_on_a_port_until_power_is_good_on_that_port: (descriptor_body.u8(descriptor_index::<5>()) as u16) * 2,
						
						maximum_current_requirement_scalar: descriptor_body.u8(descriptor_index::<6>()),
						
						packet_header_decode_latency: PacketHeaderDecodeLatency::parse(descriptor_body.u8(descriptor_index::<7>())),
					
						maximum_delay_in_nanoseconds: descriptor_body.u16(descriptor_index::<8>()),
					
						downstream_ports: Self::downstream_ports_parse(descriptor_body)?,
					}
				)
			)
		)
	}
	
	#[inline(always)]
	fn downstream_ports_parse(descriptor_body: &[u8]) -> Result<DownstreamPorts<Version3DownstreamPortSetting>, Version3HubDescriptorParseError>
	{
		use Version3HubDescriptorParseError::*;
		
		let number_of_downstream_ports =
		{
			let bNbrPorts = descriptor_body.u8(descriptor_index::<2>());
			if unlikely!(bNbrPorts > 15)
			{
				return Err(MoreThan15Ports { bNbrPorts })
			}
			bNbrPorts as usize
		};
		
		let device_removable = descriptor_body.u16(descriptor_index::<10>()) as usize;
		
		let mut port_settings = Vec::new_with_capacity(number_of_downstream_ports).map_err(CouldNotAllocatePortsSettings)?;
		for port_number in 1 ..= number_of_downstream_ports
		{
			port_settings.push_unchecked
			(
				Version3DownstreamPortSetting
				{
					device_is_removable: ((device_removable >> port_number) & 0b1) != 0,
				}
			)
		}
		Ok(DownstreamPorts(port_settings))
	}
}
