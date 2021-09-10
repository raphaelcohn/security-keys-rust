// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Variant.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Variant
{
	/// Reserved for Apollo NCS.
	ApolloNetworkComputerSystemBackwardCompatibility,
	
	/// RFC 4122 variant.
	Rfc4122,
	
	/// Reserved for backward compatibility with Microsoft globally unique identifiers (GUID) eg those used in the legacy COM technology.
	MicrosoftGloballyUniqueIdentifier,

	#[allow(missing_docs)]
	ReservedForFutureUse,
}
