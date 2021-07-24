// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


pub(in super) fn validate_info_plist_ifd_ccid(info_plist: &Dictionary) -> Result<(), &'static str>
{
	#[inline(always)]
	fn validate_u16_string(u16_string: &String, incorrect_length: &'static str, not_a_hexadecimal_number: &'static str, validate_value: impl FnOnce(u16) -> Result<(), &'static str>) -> Result<(), &'static str>
	{
		/// `0x`.
		const PrefixLength: usize = 2;
		
		const Length: usize = PrefixLength + (size_of::<u16>() * 2);
		
		let value = u16_string.as_bytes();
		if unlikely!(value.len() != Length)
		{
			return Err(incorrect_length)
		}
		
		let value = u16::parse_hexadecimal_number_upper_or_lower_case_with_0x_prefix(value).map_err(|_| not_a_hexadecimal_number)?;
		validate_value(value)
	}
	
	#[inline(always)]
	fn validate_u16_value(u16_value: &Value, not_a_string: &'static str, incorrect_length: &'static str, not_a_hexadecimal_number: &'static str, validate_value: impl FnOnce(u16) -> Result<(), &'static str>) -> Result<(), &'static str>
	{
		if let Value::String(u16_string) = u16_value
		{
			validate_u16_string(u16_string, incorrect_length, not_a_hexadecimal_number, validate_value)
		}
		else
		{
			Err(not_a_string)
		}
	}
	
	#[inline(always)]
	fn validate_log_level(log_level: u16, error: &'static str) -> Result<(), &'static str>
	{
		const DEBUG_LEVEL_CRITICAL: u16 = 1;
		const DEBUG_LEVEL_INFO: u16 = 2;
		const DEBUG_LEVEL_COMM: u16 = 4;
		const DEBUG_LEVEL_PERIODIC: u16 = 8;
		const ValidLogLevels: u16 = DEBUG_LEVEL_CRITICAL | DEBUG_LEVEL_INFO | DEBUG_LEVEL_COMM | DEBUG_LEVEL_PERIODIC;
		if (log_level & !ValidLogLevels) != 0
		{
			Err(error)
		}
		else
		{
			Ok(())
		}
	}
	
	#[inline(always)]
	fn validate_ifdLogLevel(info_plist: &Dictionary) -> Result<(), &'static str>
	{
		if let Some(ifdLogLevel) = info_plist.get("ifdLogLevel")
		{
			validate_u16_value(ifdLogLevel, "ifdLogLevel is not a string", "ifdLogLevel is not the correct length", "ifdLogLevel is not a hexadecimal number starting 0x", |log_level| validate_log_level(log_level, "ifdLogLevel includes invalid log levels"))
		}
		else
		{
			Ok(())
		}
	}
	
	#[inline(always)]
	fn validate_ifdDriverOptions(info_plist: &Dictionary) -> Result<(), &'static str>
	{
		if let Some(ifdDriverOptions) = info_plist.get("ifdDriverOptions")
		{
			validate_u16_value(ifdDriverOptions, "ifdDriverOptions is not a string", "ifdDriverOptions is not the correct length", "ifdDriverOptions is not a hexadecimal number", |driver_options|
			{
				const DRIVER_OPTION_CCID_EXCHANGE_AUTHORIZED: u16 = 0x01;
				const DRIVER_OPTION_GEMPC_TWIN_KEY_APDU: u16 = 0x02;
				const DRIVER_OPTION_USE_BOGUS_FIRMWARE: u16 = 0x04;
				const PowerBits: u16 = 0b11_0000; // 0x30.
				const DRIVER_OPTION_DISABLE_PIN_RETRIES: u16 = 0x40;
				const ValidDriverOptions: u16 = DRIVER_OPTION_CCID_EXCHANGE_AUTHORIZED | DRIVER_OPTION_GEMPC_TWIN_KEY_APDU | DRIVER_OPTION_USE_BOGUS_FIRMWARE | PowerBits | DRIVER_OPTION_DISABLE_PIN_RETRIES;
				if (driver_options & !ValidDriverOptions) != 0
				{
					Err("ifdDriverOptions includes invalid bits")
				}
				else
				{
					Ok(())
				}
			})
		}
		else
		{
			Ok(())
		}
	}
	
	#[inline(always)]
	fn validate_string_key_is_present(info_plist: &Dictionary, key: &'static str, error: &'static str) -> Result<(), &'static str>
	{
		if let Some(Value::String(_)) = info_plist.get(key)
		{
			Ok(())
		}
		else
		{
			Err(error)
		}
	}
	
	#[inline(always)]
	fn validate_LIBCCID_ifdLogLevel() -> Result<(), &'static str>
	{
		if let Some(ifdLogLevel) = var_os("LIBCCID_ifdLogLevel")
		{
			let string = ifdLogLevel.into_string().map_err(|_| "LIBCCID_ifdLogLevel is not a UTF-8 string")?;
			validate_u16_string(&string, "LIBCCID_ifdLogLevel is not the correct length", "ifdLogLevel is not a hexadecimal number starting 0x", |log_level| validate_log_level(log_level, "LIBCCID_ifdLogLevel includes invalid log levels"))
		}
		else
		{
			Ok(())
		}
	}
	
	validate_ifdLogLevel(info_plist)?;
	validate_ifdDriverOptions(info_plist)?;
	validate_string_key_is_present(info_plist, "ifdManufacturerString", "ifdManufacturerString key with a string value is missing")?;
	validate_string_key_is_present(info_plist, "ifdProductString", "ifdProductString key with a string value is missing")?;
	validate_string_key_is_present(info_plist, "Copyright", "Copyright key with a string value is missing")?;
	validate_LIBCCID_ifdLogLevel()?;
	
	Ok(())
}
