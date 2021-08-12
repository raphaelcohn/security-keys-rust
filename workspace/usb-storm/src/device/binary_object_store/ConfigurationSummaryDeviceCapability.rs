// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Configuration summary.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationSummaryDeviceCapability
{
	version: Version,

	class_code: u8,

	subclass_code: u8,

	protocol: u8,

	configuration_descriptor_indices: WrappedIndexSet<u8>,
}

impl ConfigurationSummaryDeviceCapability
{
	/// Normally 1.0.
	#[inline(always)]
	pub const fn version(&self) -> Version
	{
		self.version
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn class_code(&self) -> u8
	{
		self.class_code
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn subclass_code(&self) -> u8
	{
		self.subclass_code
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn protocol(&self) -> u8
	{
		self.protocol
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn configuration_descriptor_indices(&self) -> &WrappedIndexSet<u8>
	{
		&self.configuration_descriptor_indices
	}
	
	#[inline(always)]
	fn parse(device_capability_bytes: &[u8]) -> Result<Self, ConfigurationSummaryDeviceCapabilityParseError>
	{
		use ConfigurationSummaryDeviceCapabilityParseError::*;
		
		const MinimumSize: usize = 9 - 3;
		if unlikely!(device_capability_bytes.len() < MinimumSize)
		{
			return Err(TooShort)
		}
		
		let version = device_capability_bytes.version_unadjusted(0)?;
		
		let class_code = device_capability_bytes.u8_unadjusted(2);
		let subclass_code = device_capability_bytes.u8_unadjusted(3);
		let protocol = device_capability_bytes.u8_unadjusted(4);
		let bConfigurationCount = device_capability_bytes.u8_unadjusted(5);
		
		if unlikely!(bConfigurationCount > MaximumNumberOfConfigurations)
		{
			return Err(TooManyConfigurations { bConfigurationCount })
		}
		
		let configuration_descriptor_indices =
		{
			let mut configuration_descriptor_indices = WrappedIndexSet::with_capacity(bConfigurationCount).map_err(OutOfMemoryForConfigurationDescriptorIndices)?;
			for offset in 0..bConfigurationCount
			{
				let configuration_descriptor_index = device_capability_bytes.u8_unadjusted((6 + offset) as usize);
				let outcome = configuration_descriptor_indices.insert(configuration_descriptor_index);
				if unlikely!(outcome == false)
				{
					return Err(DuplicateConfigurationIndex { configuration_descriptor_index })
				}
			}
			configuration_descriptor_indices
		};
		
		Ok
		(
			Self
			{
				version,
				
				class_code,
				
				subclass_code,
				
				protocol,
				
				configuration_descriptor_indices
			}
		)
	}
}
