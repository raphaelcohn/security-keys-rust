// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::CardError;
use likely::unlikely;
use std::num::NonZeroU8;
use swiss_army_knife::get_unchecked::GetUnchecked;


include!("ApplicationInformation.rs");
include!("ApplicationError.rs");
include!("ApplicationWarning.rs");
include!("ClassCodeError.rs");
include!("ClassFunctionError.rs");
include!("CommandNotAllowedError.rs");
include!("InstructionCodeError.rs");
include!("InternalExceptionError.rs");
include!("LengthError.rs");
include!("ResponseCode.rs");
include!("ResponseLevel.rs");
include!("SecurityError.rs");
include!("StateOfNonVolatileMemoryChangedError.rs");
include!("StateOfNonVolatileMemoryChangedWarning.rs");
include!("StateOfNonVolatileMemoryUnchangedError.rs");
include!("StateOfNonVolatileMemoryUnchangedWarning.rs");
include!("u2.rs");
include!("u4.rs");
include!("WrongLengthLeError.rs");
include!("WrongParametersVariant1Error.rs");
include!("WrongParametersVariant2Error.rs");
