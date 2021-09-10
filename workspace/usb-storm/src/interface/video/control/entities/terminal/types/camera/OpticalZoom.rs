// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Optical zoom.
///
/// Divide objective focal length by ocular focal length to obtain the magnification ratio; if the objective focal length is less than the ocular focal length the lens takes wide-angle images.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpticalZoom
{
	objective_zoom_range: RangeInclusive<FocalLength>,
	
	ocular: FocalLength,
}

impl PartialOrd for OpticalZoom
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering>
	{
		Some(self.cmp(other))
	}
}

impl Ord for OpticalZoom
{
	#[inline(always)]
	fn cmp(&self, other: &Self) -> Ordering
	{
		#[inline(always)]
		fn compare_scaled_values(left: &OpticalZoom, right: &OpticalZoom, start_or_end: impl Fn(&RangeInclusive<FocalLength>) -> &FocalLength) -> Ordering
		{
			#[inline(always)]
			const fn to_u32(value: FocalLength) -> u32
			{
				value.get() as u32
			}
			
			let left_unscaled = start_or_end(&left.objective_zoom_range);
			let right_unscaled = start_or_end(&right.objective_zoom_range);
			
			let left_scaled = to_u32(*left_unscaled) * to_u32(right.ocular);
			let right_scaled = to_u32(*right_unscaled) * to_u32(left.ocular);
			left_scaled.cmp(&right_scaled)
		}
		
		compare_scaled_values(self, other, RangeInclusive::start).then_with(|| compare_scaled_values(self, other, RangeInclusive::end))
	}
}

impl OpticalZoom
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn objective_zoom_range(&self) -> &RangeInclusive<FocalLength>
	{
		&self.objective_zoom_range
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn ocular(&self) -> FocalLength
	{
		self.ocular
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn normalized(&self) -> RangeInclusive<f64>
	{
		let start = f64::from_bits(self.objective_zoom_range.start().get() as u64);
		let end = f64::from_bits(self.objective_zoom_range.end().get() as u64);
		let ocular = f64::from_bits(self.ocular.get() as u64);
		(start / ocular) ..= (end / ocular)
	}
	
	#[inline(always)]
	fn parse(entity_bytes: &[u8]) -> Result<Option<Self>, CameraParseError>
	{
		use CameraParseError::*;
		
		let wObjectiveFocalLengthMin = entity_bytes.optional_non_zero_u16(entity_index::<8>());
		let wObjectiveFocalLengthMax = entity_bytes.optional_non_zero_u16(entity_index::<10>());
		let wOcularFocalLength = entity_bytes.optional_non_zero_u16(entity_index::<12>());
		let outcome = match (wObjectiveFocalLengthMin, wObjectiveFocalLengthMax, wOcularFocalLength)
		{
			(None, None, None) => None,
			
			(Some(minimum_objective), Some(maximum_objective), Some(ocular)) =>
			{
				if unlikely!(minimum_objective > maximum_objective)
				{
					return Err(MaximumObjectiveIsLessThanMinimumObjective { minimum_objective, maximum_objective, ocular })
				}
				Some
				(
					Self
					{
						objective_zoom_range: minimum_objective ..= maximum_objective,
					
						ocular,
					}
				)
			},
			
			_ => return Err(MixOfOpticalZoomAndNonZoomSettings),
		};
		Ok(outcome)
	}
}
