// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Input specific terminal type.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[derive(EnumDiscriminants)]
#[strum_discriminants(derive(PartialOrd, Ord, Hash, Deserialize, Serialize))]
#[strum_discriminants(serde(deny_unknown_fields))]
#[allow(missing_docs)]
pub enum InputSpecificTerminalType
{
	#[allow(missing_docs)]
	VendorSpecific(Vec<u8>),
	
	/// Camera sensor.
	Camera(Camera),
	
	/// Sequential media.
	MediaTransport(MediaTransport),
}

impl InputSpecificTerminalType
{
	pub(super) const MinimumBLength: u8 = 8;
	
	#[inline(always)]
	pub(super) fn parse_camera(bLengthUsize: usize, entity_bytes: &[u8], specification_version: Version) -> Result<Self, InputTerminalEntityParseError>
	{
		Ok(InputSpecificTerminalType::Camera(Camera::parse(bLengthUsize, entity_bytes, specification_version)?))
	}
	
	#[inline(always)]
	pub(super) fn parse_media_transport(bLengthUsize: usize, entity_bytes: &[u8]) -> Result<Self, InputTerminalEntityParseError>
	{
		const MinimumBLength: u8 = InputSpecificTerminalType::MinimumBLength;
		Ok(InputSpecificTerminalType::MediaTransport(MediaTransport::parse::<MinimumBLength>(bLengthUsize, entity_bytes)?))
	}
}
