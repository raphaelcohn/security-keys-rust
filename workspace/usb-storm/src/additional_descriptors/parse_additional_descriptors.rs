// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(super) fn parse_additional_descriptors<ADP: AdditionalDescriptorParser>(mut extra: &[u8], mut additional_descriptor_parser: ADP) -> Result<Vec<AdditionalDescriptor<ADP::Descriptor>>, AdditionalDescriptorParseError<ADP::Error>>
{
	use AdditionalDescriptor::*;
	use AdditionalDescriptorParseError::*;
	
	let extra_length = extra.len();
	if likely!(extra_length == 0)
	{
		return if ADP::no_descriptors_valid()
		{
			Ok(Vec::new())
		}
		else
		{
			Err(NoDescriptors)
		}
	}
	let mut additional_descriptors = Vec::new();
	let mut remaining_length = extra_length;
	
	loop
	{
		if unlikely!(remaining_length < LengthAdjustment)
		{
			return Err(NotEnoughDescriptorBytes)
		}
		
		let bLength = extra.get_unchecked_value_safe(0);
		let descriptor_length = bLength as usize;
		if unlikely!(descriptor_length > remaining_length)
		{
			return Err(DescriptorLengthExceedsRemainingBytes)
		}
		
		let descriptor_type = extra.get_unchecked_value_safe(1);
		let remaining_bytes = extra.get_unchecked_range_safe(LengthAdjustment .. );
		let (additional_descriptor, consumed_length) = match additional_descriptor_parser.parse_descriptor(bLength, descriptor_type, remaining_bytes)
		{
			Ok(Some((additional_descriptor, consumed_length))) => (Known(additional_descriptor), consumed_length),
			
			Ok(None) =>
			(
				Unknown
				{
					descriptor_type,
					
					bytes:
					{
						let descriptor_bytes = extra.get_unchecked_range_safe(LengthAdjustment .. descriptor_length);
						Vec::new_from(descriptor_bytes).map_err(CanNotAllocateUnknownDescriptorBuffer)?
					},
				},
				descriptor_length
			),
			
			Err(error) => return Err(Specific(error)),
		};
		additional_descriptors.try_push(additional_descriptor).map_err(CanNotAllocateAdditionalDescriptor)?;
		
		remaining_length = remaining_length - consumed_length;
		if remaining_length == 0
		{
			break
		}
		
		if unlikely!(ADP::multiple_descriptors_valid())
		{
			extra = extra.get_unchecked_range_safe(consumed_length .. );
			continue
		}
		else
		{
			return Err(MoreThanOneAdditionalDescriptorPresent)
		}
	}
	
	Ok(additional_descriptors)
}
