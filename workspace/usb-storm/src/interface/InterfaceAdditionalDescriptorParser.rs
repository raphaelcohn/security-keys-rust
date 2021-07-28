// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


struct InterfaceAdditionalDescriptorParser<Inner: AdditionalDescriptorParser<Descriptor: Into<InterfaceAdditionalDescriptor>, Error: Into<InterfaceAdditionalDescriptorParseError>>>
{
	inner: Inner,
}

impl<Inner: AdditionalDescriptorParser<Descriptor: Into<InterfaceAdditionalDescriptor>, Error: Into<InterfaceAdditionalDescriptorParseError>>> AdditionalDescriptorParser for InterfaceAdditionalDescriptorParser<Inner>
{
	type Descriptor = InterfaceAdditionalDescriptor;
	
	type Error = InterfaceAdditionalDescriptorParseError;
	
	#[inline(always)]
	fn no_descriptors_valid() -> bool
	{
		Inner::no_descriptors_valid()
	}
	
	#[inline(always)]
	fn multiple_descriptors_valid() -> bool
	{
		Inner::multiple_descriptors_valid()
	}
	
	#[inline(always)]
	fn parse_descriptor(&mut self, descriptor_type: DescriptorType, bytes: &[u8]) -> Result<Option<Self::Descriptor>, Self::Error>
	{
		match self.inner.parse_descriptor(descriptor_type, bytes)
		{
			Ok(Some(ok)) => Ok(Some(ok.into())),
			
			Ok(None) => Ok(None),
			
			Err(cause) => Err(cause.into())
		}
	}
}

impl<Inner: AdditionalDescriptorParser<Descriptor: Into<InterfaceAdditionalDescriptor>, Error: Into<InterfaceAdditionalDescriptorParseError>>> InterfaceAdditionalDescriptorParser<Inner>
{
	#[inline(always)]
	fn parse_additional_descriptors(extra: Option<&[u8]>, inner: Inner) -> Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>
	{
		let this = Self
		{
			inner
		};
		parse_additional_descriptors(extra, this)
	}
}
