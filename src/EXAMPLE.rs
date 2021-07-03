// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


// See <https://crates.io/crates/openpgp-card>
#[allow(missing_docs)]
fn EXAMPLE() -> Result<(), ActivityError>
{
	let yubico_reader_name = CString::new("Yubico Yubikey 4 OTP U2F CCID").unwrap();
	
	let context = Context::new_user_scope()?;
	let yubico_present = context.use_reader_names(|reader_names|
	{
		for reader_name in reader_names
		{
			if reader_name == yubico_reader_name.as_c_str()
			{
				return true
			}
		}
		false
	})?;
	
	if !yubico_present
	{
		return Err(ActivityError::NoYubicoReaderPresent)
	}
	
	let mut card = context.connect_to_card_reader_shared(&yubico_reader_name)?.ok_or(ActivityError::NoSmartCardPresent)?;
	
	card.get_status(|_reader_names, _protocol, _answer_to_reset|
	{
	})?;
	
	card.start_transaction(|transaction|
	{
		transaction.get_status(|_reader_names, _protocol, _answer_to_reset|
		{
		})?;
		
		
		Ok(())
	})?;
	
	Ok(())
}
