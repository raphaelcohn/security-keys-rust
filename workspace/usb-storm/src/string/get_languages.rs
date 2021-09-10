// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn get_languages(device_handle: NonNull<libusb_device_handle>) -> Result<DeadOrAlive<Option<Vec<(LanguageIdentifier, Language)>>>, GetLanguagesError>
{
	use GetLanguagesError::*;
	
	let mut buffer: [MaybeUninit<u8>; MaximumStandardUsbDescriptorLength] = MaybeUninit::uninit_array();
	let remaining_bytes = return_ok_if_dead_or_alive_none!(get_string_device_descriptor_languages(device_handle, &mut buffer)?);
	
	let array_length_in_bytes = remaining_bytes.len();
	const ArrayElementSize: usize = 2;
	if unlikely!(array_length_in_bytes % ArrayElementSize != 0)
	{
		return Err(NotACorrectArraySize)
	}
	
	let array_length_in_u16 = array_length_in_bytes / ArrayElementSize;
	let array = unsafe { from_raw_parts(remaining_bytes.as_ptr() as *const u16, array_length_in_u16) };
	
	let mut duplicate_language_identifiers = WrappedHashSet::with_capacity(array_length_in_u16).map_err(CouldNotAllocateDuplicateLanguages)?;
	
	let languages = Vec::new_populated(array_length_in_u16, CouldNotAllocateLanguages, |index|
	{
		let language_identifier = u16::from_le(array.get_unchecked_value_safe(index));
		let language = Language::parse(language_identifier);
		
		let inserted = duplicate_language_identifiers.insert(language_identifier);
		if unlikely!(!inserted)
		{
			return Err(DuplicateLanguage { language })
		}
		
		Ok((language_identifier, language))
	})?;
	
	Ok(Alive(Some(languages)))
}
