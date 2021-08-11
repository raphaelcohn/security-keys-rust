// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn get_string_device_descriptor(device_handle: NonNull<libusb_device_handle>, buffer: &mut [MaybeUninit<u8>; MaximumStandardUsbDescriptorLength], descriptor_index: Option<NonZeroU8>, language_identifier: u16) -> Result<DeadOrAlive<Option<&[u8]>>, GetStandardUsbDescriptorError>
{
	const descriptor_type: DescriptorType = LIBUSB_DT_STRING;
	let descriptor_bytes = get_standard_device_descriptor(device_handle, buffer.get_unchecked_range_mut_safe(..), descriptor_type, unsafe { transmute(descriptor_index) }, language_identifier)?;
	match StandardUsbDescriptorError::parse::<descriptor_type>(descriptor_bytes)?
	{
		Dead => Ok(Dead),
		
		Alive(None) => Ok(Alive(None)),
		
		Alive(Some((remaining_bytes, bLength))) =>
		{
			let length = (bLength as usize) - DescriptorHeaderLength;
			Ok(Alive(Some(remaining_bytes.get_unchecked_range_safe(.. length))))
		}
	}
}
