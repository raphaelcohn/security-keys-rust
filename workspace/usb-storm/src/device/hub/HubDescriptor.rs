// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Hub descriptor.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum HubDescriptor
{
	#[allow(missing_docs)]
	Version2(Version2HubDescriptor),

	#[allow(missing_docs)]
	Version3(Version3HubDescriptor),
}

impl HubDescriptor
{
	pub(super) fn get_and_parse(device_connection: &DeviceConnection, device_class: DeviceClass, maximum_supported_usb_version: Version) -> Result<DeadOrAlive<Option<Self>>, HubDescriptorParseError>
	{
		use HubDescriptor::*;
		use HubDescriptorParseError::*;
		
		let outcome = match device_class
		{
			DeviceClass::Hub(_) => if maximum_supported_usb_version.is_2()
			{
				let dead_or_alive = Version2HubDescriptor::get_and_parse(device_connection).map_err(Version2Parse)?;
				match return_ok_if_dead!(dead_or_alive)
				{
					None => None,
					
					Some(hub_descriptor) => Some(Version2(hub_descriptor))
				}
			}
			else if maximum_supported_usb_version.is_3()
			{
				let dead_or_alive = Version3HubDescriptor::get_and_parse(device_connection).map_err(Version3Parse)?;
				match return_ok_if_dead!(dead_or_alive)
				{
					None => None,
					
					Some(hub_descriptor) => Some(Version3(hub_descriptor))
				}
			}
			else
			{
				None
			},
			
			_ => None,
		};
		Ok(Alive(outcome))
	}
	
}
