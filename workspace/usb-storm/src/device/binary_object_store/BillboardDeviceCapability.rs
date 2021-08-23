// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Billboard device capability.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BillboardDeviceCapability
{
	url: Option<LocalizedStrings>,
	
	vconn_power: Option<BillboardVconnPowerInWatts>,
	
	version: Version,
	
	device_container_failed_because: Option<BillboardDeviceContainerFailedBecause>,
	
	alternate_modes: Vec<BillboardAlternateMode>,
	
	preferred_alternate_mode_index: u8,
}

impl BillboardDeviceCapability
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn url(&self) -> Option<&LocalizedStrings>
	{
		self.url.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn vconn_power(&self) -> Option<BillboardVconnPowerInWatts>
	{
		self.vconn_power
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn version(&self) -> Version
	{
		self.version
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn device_container_failed_because(&self) -> Option<BillboardDeviceContainerFailedBecause>
	{
		self.device_container_failed_because
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn alternate_modes(&self) -> &[BillboardAlternateMode]
	{
		&self.alternate_modes
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn preferred_alternate_mode(&self) -> &BillboardAlternateMode
	{
		self.alternate_modes.get_unchecked_safe(self.preferred_alternate_mode_index)
	}
	
	const MinimumBLength: usize = 44;
	
	#[inline(always)]
	fn parse(device_capability_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, BillboardDeviceCapabilityParseError>
	{
		use BillboardDeviceCapabilityParseError::*;
		
		const MinimumBLength: usize = BillboardDeviceCapability::MinimumBLength;
		let length = device_capability_bytes.len();
		const MinimumSize: usize = minimum_size::<MinimumBLength>();
		if unlikely!(length < MinimumSize)
		{
			return Err(ShorterThanMinimumSize)
		}
		
		let number_of_alternate_modes = BillboardAlternateMode::parse_number_of_alternate_modes(device_capability_bytes)?;
		
		let preferred_alternate_mode_index = device_capability_bytes.u8(capability_descriptor_index::<5>());
		if unlikely!((preferred_alternate_mode_index as usize) >= number_of_alternate_modes)
		{
			return Err(PreferredAlternateModeIndexTooLarge { preferred_alternate_mode_index, number_of_alternate_modes: number_of_alternate_modes as u8 })
		}
		
		let configuration_result = device_capability_bytes.bytes(capability_descriptor_index::<8>(), 32);
		let alternate_modes = return_ok_if_dead!(BillboardAlternateMode::parse_alternate_modes(device_capability_bytes.get_unchecked_range_safe(MinimumSize .. ), number_of_alternate_modes, configuration_result, string_finder)?);
		
		let version = device_capability_bytes.version(capability_descriptor_index::<40>()).map_err(VersionParse)?;
		
		Ok
		(
			Alive
			(
				Self
				{
					url: return_ok_if_dead!(string_finder.find_string(device_capability_bytes.u8(capability_descriptor_index::<4>())).map_err(InvalidAdditionalInformationUrl)?),
					
					version,
					
					vconn_power: BillboardVconnPowerInWatts::parse(device_capability_bytes),
					
					device_container_failed_because: BillboardDeviceContainerFailedBecause::parse(version, device_capability_bytes),
					
					alternate_modes,
					
					preferred_alternate_mode_index,
				}
			)
		)
	}
	
}
