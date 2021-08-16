// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
fn parse_controls_by_channel_number<Controls, E: error::Error, ControlsError: error::Error>(entity_body: &[u8], controls_parser: impl FnOnce(u32) -> Result<Controls, ControlsError> + Copy, controls_length_error: E, memory_allocation_error: impl FnOnce(TryReserveError) -> E, controls_parser_error: impl FnOnce(ControlsError, u8) -> E + Copy) -> Result<ChannelControlsByChannelNumber<Controls>, E>
{
	let entity_body_minimum_size = (Version2EntityDescriptors::FeatureUnitMinimumBLength as usize) - DescriptorEntityMinimumLength;
	let entity_body_length = entity_body.len();
	let bmaControlsSize = entity_body_length - entity_body_minimum_size;
	const bmaControlSize: usize = size_of::<u32>();
	if unlikely!(bmaControlsSize % bmaControlSize != 0)
	{
		return Err(controls_length_error)
	}
	
	let number_of_channels_including_master = bmaControlsSize / bmaControlSize;
	
	let channel_controls_by_channel_number = Vec::new_populated(number_of_channels_including_master, memory_allocation_error, |channel_index|
	{
		let bmaControls = entity_body.u32(entity_index_non_constant(5 + (channel_index * bmaControlSize)));
		controls_parser(bmaControls).map_err(|cause| controls_parser_error(cause, channel_index as u8))
	})?;
	
	Ok(ChannelControlsByChannelNumber(channel_controls_by_channel_number))
}
