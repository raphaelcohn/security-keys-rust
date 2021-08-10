// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[allow(missing_docs)]
#[derive(Copy, Clone, Eq)]
#[allow(missing_docs)]
pub union UnitOrTerminalEntityIdentifier
{
	terminal: TerminalEntityIdentifier,
	
	unit: UnitEntityIdentifier,
}

impl Serialize for UnitOrTerminalEntityIdentifier
{
	#[inline(always)]
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
	{
		self.entity_identifier().serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for UnitOrTerminalEntityIdentifier
{
	#[inline(always)]
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
	{
		EntityIdentifier::deserialize(deserializer).map(Self::new)
	}
}

impl Debug for UnitOrTerminalEntityIdentifier
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		self.entity_identifier().fmt(f)
	}
}

impl PartialEq for UnitOrTerminalEntityIdentifier
{
	#[inline(always)]
	fn eq(&self, rhs: &Self) -> bool
	{
		self.entity_identifier() == rhs.entity_identifier()
	}
}

impl PartialOrd for UnitOrTerminalEntityIdentifier
{
	#[inline(always)]
	fn partial_cmp(&self, rhs: &Self) -> Option<Ordering>
	{
		Some(self.cmp(rhs))
	}
}

impl Ord for UnitOrTerminalEntityIdentifier
{
	#[inline(always)]
	fn cmp(&self, rhs: &Self) -> Ordering
	{
		self.entity_identifier().cmp(&rhs.entity_identifier())
	}
}

impl Hash for UnitOrTerminalEntityIdentifier
{
	#[inline(always)]
	fn hash<H: Hasher>(&self, state: &mut H)
	{
		self.entity_identifier().hash(state)
	}
}

impl UnitOrTerminalEntityIdentifier
{
	#[inline(always)]
	pub(super) const fn new(entity_identifier: EntityIdentifier) -> Self
	{
		Self
		{
			terminal: entity_identifier
		}
	}
	
	#[inline(always)]
	const fn entity_identifier(self) -> EntityIdentifier
	{
		unsafe { self.terminal }
	}
}
