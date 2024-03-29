// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Sampling frequency
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum SamplingFrequency
{
	#[allow(missing_docs)]
	Continuous
	{
		lower_bound: Hertz,
		
		upper_bound: Hertz,
	},
	
	#[allow(missing_docs)]
	Discrete
	{
		/// Will always have at least one element.
		sampling_frequencies: Vec<Hertz>,
	}
}

impl SamplingFrequency
{
	#[inline(always)]
	fn parse<const MinimumBLength: u8>(descriptor_body: &[u8], bLength: u8) -> Result<Self, SamplingFrequencyParseError>
	{
		use SamplingFrequencyParseError::*;
		
		let minimum_b_length = MinimumBLength as usize;
		const U24Size: usize = 3;
		
		let index = minimum_b_length - 1;
		
		use SamplingFrequency::*;
		let sampling_frequency = match descriptor_body.optional_non_zero_u8(descriptor_index_non_constant(index))
		{
			None =>
			{
				let expected_length = minimum_b_length + (U24Size * 2);
				if unlikely!((bLength as usize) < expected_length)
				{
					return Err(ContinuousSamplingFrequencyBLengthWrong { bLength })
				}
				
				let length = DescriptorHeaderLength + descriptor_body.len();
				if unlikely!(length < expected_length)
				{
					return Err(ContinuousSamplingFrequencyLengthWrong { length })
				}
				
				let lower_bound = descriptor_body.u24_as_u32(descriptor_index_non_constant(index));
				let upper_bound = descriptor_body.u24_as_u32(descriptor_index_non_constant(index + U24Size));
				if unlikely!(lower_bound > upper_bound)
				{
					return Err(ContinuousSamplingFrequencyBoundsNegative { lower_bound, upper_bound })
				}
				
				Continuous
				{
					lower_bound,
					
					upper_bound,
				}
			}
			
			Some(count) =>
			{
				let count = count.get() as usize;
				let expected_length = minimum_b_length + (count * U24Size);
				
				if unlikely!((bLength as usize) < expected_length)
				{
					return Err(DiscreteSamplingFrequencyBLengthWrong { bLength })
				}
				
				let length = DescriptorHeaderLength + descriptor_body.len();
				if unlikely!(length < expected_length)
				{
					return Err(DiscreteSamplingFrequencyLengthWrong { length })
				}
				
				Discrete
				{
					sampling_frequencies:  Vec::new_populated(count, CouldNotAllocateMemoryForDiscreteSamplingFrequencies, |sample_index|
					{
						Ok(descriptor_body.u24_as_u32(descriptor_index_non_constant(index + (sample_index * U24Size))))
					})?,
				}
			}
		};
		Ok(sampling_frequency)
	}
}
