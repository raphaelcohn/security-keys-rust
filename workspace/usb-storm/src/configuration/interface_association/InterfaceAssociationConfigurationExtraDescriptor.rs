// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An interface association descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceAssociationConfigurationExtraDescriptor
{
	associated_interfaces: AssociatedInterfaces,
	
	function: FunctionClass,
	
	description: Option<LocalizedStrings>,
}

impl InterfaceAssociationConfigurationExtraDescriptor
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn associated_interfaces(&self) -> AssociatedInterfaces
	{
		self.associated_interfaces.clone()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn function(&self) -> FunctionClass
	{
		self.function
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[inline(always)]
	fn parse(descriptor_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, InterfaceAssociationConfigurationExtraDescriptorParseError>
	{
		use InterfaceAssociationConfigurationExtraDescriptorParseError::*;
		
		Ok
		(
			Alive
			(
				Self
				{
					associated_interfaces: AssociatedInterfaces::parse(descriptor_body)?,
					
					function:
					{
						let bFunctionClass = descriptor_body.u8(descriptor_index::<4>());
						let bFunctionSubClass = descriptor_body.u8(descriptor_index::<5>());
						let bFunctionProtocol = descriptor_body.u8(descriptor_index::<6>());
						
						FunctionClass::parse(bFunctionClass, bFunctionSubClass, bFunctionProtocol).map_err(FunctionClassParse)?
					},
					
					description:
					{
						let description = string_finder.find_string(descriptor_body.u8(descriptor_index::<7>())).map_err(InvalidDescriptionString)?;
						return_ok_if_dead!(description)
					},
				}
			)
		)
	}
}
