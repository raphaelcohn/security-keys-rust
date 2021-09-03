// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An USB interface.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub struct Interface(WrappedIndexMap<AlternateSettingNumber, AlternateSetting>);

impl Interface
{
	/// Interface alternate settings; the first alternate setting is the one in use.
	#[inline(always)]
	pub fn alternate_settings(&self) -> &IndexMap<AlternateSettingNumber, AlternateSetting>
	{
		&self.0
	}
	
	#[inline(always)]
	pub(super) fn parse(libusb_interface: &libusb_interface, device_connection: &DeviceConnection, interface_index: u8, maximum_supported_usb_version: Version, speed: Option<Speed>) -> Result<DeadOrAlive<(InterfaceNumber, Self)>, InterfaceParseError>
	{
		let (number_of_alternate_settings, alternate_settings_slice) = Self::parse_alternate_settings_slice(libusb_interface, interface_index)?;
		
		let mut alternate_settings = WrappedIndexMap::with_capacity(number_of_alternate_settings).map_err(InterfaceParseError::CouldNotAllocateMemoryForAlternateSettings)?;
		
		let interface_number = return_ok_if_dead!(Self::parse_alternate_setting(alternate_settings_slice, device_connection, interface_index, 0, &mut alternate_settings, maximum_supported_usb_version, speed)?);
		
		for alternate_setting_index in 1 .. number_of_alternate_settings.get()
		{
			let parsed_interface_number = return_ok_if_dead!(Self::parse_alternate_setting(alternate_settings_slice, device_connection, interface_index, alternate_setting_index, &mut alternate_settings, maximum_supported_usb_version, speed)?);
			if unlikely!(interface_number != parsed_interface_number)
			{
				return Err(InterfaceParseError::AlternateSettingHasDifferentIndexNumber { interface_index, interface_number, parsed_interface_number, alternate_setting_index: new_non_zero_u8(alternate_setting_index) })
			}
		}
		
		Ok(Alive((interface_number, Self(alternate_settings))))
	}
	
	#[inline(always)]
	fn parse_alternate_setting(alternate_settings_slice: &[libusb_interface_descriptor], device_connection: &DeviceConnection, interface_index: u8, alternate_setting_index: u8, alternate_settings: &mut WrappedIndexMap<AlternateSettingNumber, AlternateSetting>, maximum_supported_usb_version: Version, speed: Option<Speed>) -> Result<DeadOrAlive<InterfaceNumber>, AlternateSettingParseError>
	{
		let alternate_setting = alternate_settings_slice.get_unchecked_safe(alternate_setting_index);
		let (interface_number, alternate_setting_number, alternate_setting) = return_ok_if_dead!(AlternateSetting::parse(device_connection, alternate_setting, interface_index, alternate_setting_index, maximum_supported_usb_version, speed)?);
		
		let outcome = alternate_settings.insert(alternate_setting_number, alternate_setting);
		if unlikely!(outcome.is_some())
		{
			return Err(AlternateSettingParseError::DuplicateAlternateSetting { interface_index, alternate_setting_index })
		}
		
		Ok(Alive(interface_number))
	}
	
	#[inline(always)]
	fn parse_alternate_settings_slice(interface: &libusb_interface, interface_index: u8) -> Result<(NonZeroU8, &[libusb_interface_descriptor]), InterfaceParseError>
	{
		use InterfaceParseError::*;
		
		let alternate_settings_pointer = interface.altsetting;
		if unlikely!(alternate_settings_pointer.is_null())
		{
			return Err(NullAlternateSettingsPointer { interface_index })
		}
		
		let number_of_alternate_settings = interface.num_altsetting;
		if unlikely!(number_of_alternate_settings < 0)
		{
			return Err(NegativeNumberOfAlternateSettings { interface_index })
		}
		else if unlikely!(number_of_alternate_settings == 0)
		{
			return Err(NoAlternateSettings { interface_index })
		}
		else if unlikely!(number_of_alternate_settings > MaximumNumberOfAlternateSettings)
		{
			return Err(TooManyAlternateSettings { interface_index })
		}
		
		Ok
		(
			(
				new_non_zero_u8(number_of_alternate_settings as u8),
				unsafe { from_raw_parts(alternate_settings_pointer, number_of_alternate_settings as usize) }
			)
		)
	}
}
