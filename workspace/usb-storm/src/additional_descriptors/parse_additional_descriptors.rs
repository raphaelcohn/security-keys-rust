// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(super) fn parse_additional_descriptors<ADP: AdditionalDescriptorParser>(string_finder: &StringFinder, mut extra: &[u8], mut additional_descriptor_parser: ADP) -> Result<DeadOrAlive<Vec<AdditionalDescriptor<ADP::Descriptor>>>, AdditionalDescriptorParseError<ADP::Error>>
{
	use AdditionalDescriptor::*;
	use AdditionalDescriptorParseError::*;
	
	let extra_length = extra.len();
	if likely!(extra_length == 0)
	{
		return Ok(Alive(Vec::new()))
	}
	let mut additional_descriptors = Vec::new();
	let mut remaining_length = extra_length;
	
	loop
	{
		if unlikely!(remaining_length < DescriptorHeaderLength)
		{
			return Err(NotEnoughDescriptorBytes)
		}
		
		let bLength = extra.u8_unadjusted(0);
		let descriptor_length = bLength as usize;
		if unlikely!(descriptor_length > remaining_length)
		{
			return Err(DescriptorLengthExceedsRemainingBytes)
		}
		
		let descriptor_type = extra.u8_unadjusted(1);
		let remaining_bytes = extra.get_unchecked_range_safe(DescriptorHeaderLength .. );
		let (additional_descriptor, consumed_length) = match additional_descriptor_parser.parse_descriptor(string_finder, bLength, descriptor_type, remaining_bytes)
		{
			Ok(Some(Alive((additional_descriptor, consumed_length)))) => (Known(additional_descriptor), consumed_length),
			
			Ok(Some(Dead)) => return Ok(Dead),
			
			Ok(None) =>
			{
				let consumed_length = descriptor_length - DescriptorHeaderLength;
				(
					Unknown
					{
						descriptor_type,
						
						bytes:
						{
							let descriptor_bytes = remaining_bytes.get_unchecked_range_safe(.. consumed_length);
							Vec::new_from(descriptor_bytes).map_err(CanNotAllocateUnknownDescriptorBuffer)?
						},
					},
					consumed_length
				)
			}
			
			Err(error) => return Err(Specific(error)),
		};
		additional_descriptors.try_push(additional_descriptor).map_err(CanNotAllocateAdditionalDescriptor)?;
		
		let consumed_length_including_header = DescriptorHeaderLength + consumed_length;
		if remaining_length == consumed_length_including_header
		{
			break
		}
		remaining_length -= consumed_length_including_header;
		extra = extra.get_unchecked_range_safe(consumed_length_including_header .. );
	}
	
	Ok(Alive(additional_descriptors))
}
