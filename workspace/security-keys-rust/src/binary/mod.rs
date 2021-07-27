// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use clap::App;
use clap::Arg;
use clap::ArgMatches;
use clap::crate_authors;
use clap::crate_name;
use clap::crate_version;
use ron::Serializer as RonSerializer;
use ron::extensions::Extensions;
use ron::ser::PrettyConfig;
use security_keys_rust::usb::UsbDevice;
use security_keys_rust::usb::errors::UsbError;
use serde::Serialize;
use serde::Serializer;
use std::fmt::Debug;
use std::io::Write;


include!("CommandLineParser.rs");
include!("new_ron_serializer.rs");
include!("serialize.rs");
include!("usb_devices_serialize.rs");
