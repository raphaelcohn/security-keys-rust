// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn get_localized_string(device_handle: NonNull<libusb_device_handle>, string_descriptor_index: NonZeroU8, (language_identifier, language): (LanguageIdentifier, Language)) -> Result<DeadOrAlive<String>, GetLocalizedStringError>
{
	use GetLocalizedStringError::*;
	
	let mut buffer = MaybeUninit::uninit_array();
	let remaining_bytes = match get_string_device_descriptor_language(device_handle, string_descriptor_index, language_identifier, &mut buffer).map_err(|cause| GetStandardUsbDescriptor { cause, string_descriptor_index, language })?
	{
		Dead => return Ok(Dead),
		
		Alive(None) => return Err(StringIndexNonZeroButDeviceDoesNotSupportGettingString { string_descriptor_index, language }),
		
		Alive(Some(remaining_bytes)) => remaining_bytes,
	};
	
	let array_length_in_bytes = remaining_bytes.len();
	const ArrayElementSize: usize = 2;
	if unlikely!(array_length_in_bytes % ArrayElementSize != 0)
	{
		return Err(NotACorrectUtf16LittleEndianSize { string_descriptor_index, language })
	}
	
	let array_length_in_u16 = array_length_in_bytes / ArrayElementSize;
	
	// Surrogate pairs encode from 2 x u16 to 4 x bytes; no change.
	// UTF-16 LE 0xFFFF encodes to three bytes; 1.5x growth.
	let maximum_number_of_utf_8_bytes = array_length_in_bytes * 3;
	
	let mut utf_8_bytes = Vec::new_with_capacity(maximum_number_of_utf_8_bytes).map_err(|cause| CouldNotAllocateString { cause, string_descriptor_index, language })?;
	let array = unsafe { from_raw_parts(remaining_bytes.as_ptr() as *const u16, array_length_in_u16) };
	for result in decode_utf16(array.iter().cloned())
	{
		let character = result.map_err(|cause| InvalidUtf16LittleEndianSequence { cause, string_descriptor_index, language })?;
		encode_utf8_raw(character, &mut utf_8_bytes);
	}
	
	utf_8_bytes.shrink_to_fit();
	Ok(Alive(unsafe { String::from_utf8_unchecked(utf_8_bytes) }))
}
