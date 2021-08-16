// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn parse_process_type_modes<E: error::Error, LACSL: LogicalAudioChannelSpatialLocation, Output: Eq + Hash + Ord>(process_type_specific_bytes: &[u8], output_logical_audio_channel_cluster: &LogicalAudioChannelCluster<LACSL>, into_output_mode: impl Fn(WrappedBitFlags<LACSL>) -> Result<Output, E>, out_of_memory_error: impl FnOnce(TryReserveError) -> E, missing_spatial_location_error: impl FnOnce(WrappedBitFlags<LACSL>, LACSL) -> E, duplicate_error: impl FnOnce(WrappedBitFlags<LACSL>) -> E) -> Result<WrappedIndexSet<Output>, E>
{
	let bNrModes = process_type_specific_bytes.u8(0) as usize;
	
	let mut output_modes = WrappedIndexSet::with_capacity(bNrModes).map_err(out_of_memory_error)?;
	for mode_index in 0 .. bNrModes
	{
		let bit_map = LACSL::parse_mode_bit_map(process_type_specific_bytes, 1 + (mode_index * size_of::<LACSL::Numeric>()));
		
		let mode = WrappedBitFlags::from_bits_truncate(bit_map);
		for spatial_location in mode.iter()
		{
			if unlikely!(!output_logical_audio_channel_cluster.contains_spatial_channel(spatial_location))
			{
				return Err(missing_spatial_location_error(mode, spatial_location))
			}
		}
		
		let output_mode = into_output_mode(mode)?;
		
		let inserted = output_modes.insert(output_mode);
		if unlikely!(!inserted)
		{
			return Err(duplicate_error(mode))
		}
	}
	
	Ok(output_modes)
}
