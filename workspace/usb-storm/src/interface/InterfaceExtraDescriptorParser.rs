// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


struct InterfaceExtraDescriptorParser<Inner: DescriptorParser<Descriptor: Into<InterfaceExtraDescriptor>, Error: Into<InterfaceExtraDescriptorParseError>>>
{
	inner: Inner,
}

impl<Inner: DescriptorParser<Descriptor: Into<InterfaceExtraDescriptor>, Error: Into<InterfaceExtraDescriptorParseError>>> DescriptorParser for InterfaceExtraDescriptorParser<Inner>
{
	type Descriptor = InterfaceExtraDescriptor;
	
	type Error = InterfaceExtraDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, device_connection: &DeviceConnection, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		match self.inner.parse_descriptor(device_connection, bLength, descriptor_type, remaining_bytes)
		{
			Ok(Some(Alive((descriptor, consumed_length)))) => Ok(Some(Alive((descriptor.into(), consumed_length)))),
			
			Ok(Some(Dead)) => Ok(Some(Dead)),
			
			Ok(None) => Ok(None),
			
			Err(cause) => Err(cause.into())
		}
	}
	
	#[inline(always)]
	fn unknown(descriptor_type: DescriptorType, bytes: Vec<u8>) -> Self::Descriptor
	{
		InterfaceExtraDescriptor::Unknown { descriptor_type, bytes }
	}
}

impl<Inner: DescriptorParser<Descriptor: Into<InterfaceExtraDescriptor>, Error: Into<InterfaceExtraDescriptorParseError>>> InterfaceExtraDescriptorParser<Inner>
{
	#[inline(always)]
	fn parse_descriptors(device_connection: &DeviceConnection, extra: &[u8], inner: Inner) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
	{
		let this = Self
		{
			inner
		};
		parse_descriptors(device_connection, extra, this)
	}
}
