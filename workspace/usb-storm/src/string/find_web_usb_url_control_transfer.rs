// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(crate) fn find_web_usb_url_control_transfer(device_handle: NonNull<libusb_device_handle>, vendor_code: u8, url_descriptor_index: NonZeroU8, buffer: &mut [MaybeUninit<u8>]) -> Result<DeadOrAlive<Option<&[u8]>>, GetStandardUsbDescriptorError>
{
	const WEBUSB_URL: u8 = 3;
	const GET_URL: u16 = 2;
	
	let result = control_transfer_in(device_handle, (ControlTransferRequestType::Vendor, ControlTransferRecipient::Device, vendor_code), url_descriptor_index.get() as u16, GET_URL, buffer);
	let descriptor_bytes = GetDescriptorError::parse_result(result)?;
	match StandardUsbDescriptorError::parse::<WEBUSB_URL, false>(descriptor_bytes)?
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
