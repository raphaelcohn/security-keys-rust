// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An USB interface.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Interface(IndexMap<AlternateSettingNumber, AlternateSetting>);

impl Interface
{
	/// Interface alternate settings; the first alternate setting is the one in use.
	#[inline(always)]
	pub fn alternate_settings(&self) -> &IndexMap<AlternateSettingNumber, AlternateSetting>
	{
		&self.0
	}
	
	/// Does not check the alternate settings of the interface.
	#[inline(always)]
	pub(super) fn smart_card_interface_additional_descriptor(&self) -> Option<&SmartCardInterfaceAdditionalDescriptor>
	{
		self.interface_alternate_settings.get_unchecked_safe(0).smart_card_interface_additional_descriptor()
	}
	
	#[inline(always)]
	pub(super) fn parse(libusb_interface: &libusb_interface, string_finder: &StringFinder, interface_index: u8) -> Result<(InterfaceNumber, Self), InterfaceParseError>
	{
		use self::InterfaceParseError::*;
		
		let (number_of_alternate_settings, alternate_settings_slice) = Self::parse_alternate_settings_slice(libusb_interface, interface_index)?;
		
		let mut alternate_settings = IndexMap::with_capacity(number_of_alternate_settings.get() as usize);
		
		let interface_number = Self::parse_alternate_setting(string_finder, interface_index, 0, &mut alternate_settings)?;
		for alternate_setting_index in 1 .. number_of_alternate_settings.get()
		{
			let parsed_interface_number = Self::parse_alternate_setting(string_finder, interface_index, alternate_setting_index, &mut alternate_settings)?;
			if unlikely!(interface_number != parsed_interface_number)
			{
				return Err(InterfaceParseError::AlternateSettingHasDifferentIndexNumber { interface_index, interface_number, parsed_interface_number, alternate_setting_index: new_non_zero_u8(alternate_setting_index) })
			}
		}
		
		Ok((interface_number, Self(alternate_settings)))
	}
	
	#[inline(always)]
	fn parse_alternate_setting(string_finder: &StringFinder, interface_index: u8, alternate_setting_index: u8, alternate_settings: &mut IndexMap<AlternateSettingNumber, AlternateSetting>) -> Result<InterfaceNumber, AlternateSettingParseError>
	{
		let alternate_setting = alternate_settings_slice.get_unchecked_safe(alternate_setting_index);
		let (interface_number, alternate_setting_number, alternate_setting) = AlternateSetting::parse(string_finder, alternate_setting, interface_index, alternate_setting_index)?;
		
		let outcome = alternate_settings.insert(alternate_setting_number, alternate_setting);
		if unlikely!(outcome.is_some())
		{
			return Err(AlternateSettingParseError::DuplicateAlternateSetting { interface_index, alternate_setting_index })
		}
		
		Ok(interface_number)
	}
	
	#[inline(always)]
	fn parse_alternate_settings_slice(interface: &libusb_interface, interface_index: u8) -> Result<(NonZeroU8, &[libusb_interface_descriptor]), InterfaceParseError>
	{
		use self::InterfaceParseError::*;
		
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
