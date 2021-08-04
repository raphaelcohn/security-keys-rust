// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use enum_default::EnumDefault;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde::de;
use serde::de::Visitor;
use std::borrow::Borrow;
use std::borrow::Cow;
use std::convert::AsRef;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::hash::Hash;
use std::str::FromStr;
use strum_macros::AsRefStr;
use strum_macros::Display;
use strum_macros::EnumString;


include!("sub_language.rs");


include!("ArabicSubLanguage.rs");
include!("ChineseSubLanguage.rs");
include!("CyrillicOrLatinSubLanguage.rs");
include!("DutchSubLanguage.rs");
include!("EnglishSubLanguage.rs");
include!("FrenchSubLanguage.rs");
include!("GermanSubLanguage.rs");
include!("HumanInterfaceDeviceSubLanguage.rs");
include!("ItalianSubLanguage.rs");
include!("Language.rs");
include!("LanguageIdentifier.rs");
include!("KoreanSubLanguage.rs");
include!("LithuanianSubLanguage.rs");
include!("MalaySubLanguage.rs");
include!("NorwegianSubLanguage.rs");
include!("PortugueseSubLanguage.rs");
include!("SubLanguage.rs");
include!("SpanishSubLanguage.rs");
include!("SwedishSubLanguage.rs");
include!("UrduSubLanguage.rs");
