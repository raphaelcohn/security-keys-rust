// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn get_localized_string_utf16_little_endian(device_handle: NonNull<libusb_device_handle>, string_descriptor_index: NonZeroU8, (language_identifier, language): (LanguageIdentifier, Language), buffer: &mut [MaybeUninit<u8>; MaximumStandardUsbDescriptorLength]) -> Result<DeadOrAlive<Option<(&[u8], usize)>>, GetLocalizedUtf16LittleEndianStringError>
{
	use GetLocalizedUtf16LittleEndianStringError::*;
	
	let remaining_bytes = match get_string_device_descriptor_language(device_handle, string_descriptor_index, language_identifier, buffer).map_err(|cause| GetStandardUsbDescriptor { cause, string_descriptor_index, language })?
	{
		Dead => return Ok(Dead),
		
		Alive(None) => return Ok(Alive(None)),
		
		Alive(Some(remaining_bytes)) => remaining_bytes,
	};
	
	let array_length_in_bytes = remaining_bytes.len();
	const ArrayElementSize: usize = 2;
	if unlikely!(array_length_in_bytes % ArrayElementSize != 0)
	{
		return Err(NotACorrectUtf16LittleEndianSize { string_descriptor_index, language })
	}
	
	let array_length_in_u16 = array_length_in_bytes / ArrayElementSize;
	
	Ok(Alive(Some((remaining_bytes, array_length_in_u16))))
}
