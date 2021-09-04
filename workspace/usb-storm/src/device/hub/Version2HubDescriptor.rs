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
	
	ports_settings: PortsSetting<Version2PortSetting>,
}

impl HubDescriptorTrait for Version2HubDescriptor
{
	type PS = Version2PortSetting;
	
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
	fn ports_settings(&self) -> &PortsSetting<Self::PS>
	{
		&self.ports_settings
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
						
						ports_settings: PortsSetting::version_2_parse(descriptor_body)?,
					}
				)
			)
		)
	}
}
