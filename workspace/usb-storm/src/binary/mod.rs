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
use usb_storm::simple_serializer::SimpleSerializer;
use usb_storm::UsbDevice;
use usb_storm::errors::UsbError;
use serde::Serialize;
use serde::Serializer;
use serde_lexpr::to_writer as lisp_s_expression_writer;
use serde_yaml::Serializer as YamlSerializer;
use std::fmt::Debug;
use std::io::Write;
use std::path::Path;


include!("CommandLineParser.rs");
include!("new_ron_serializer.rs");
include!("serialize.rs");
include!("usb_devices_serialize.rs");
include!("write.rs");
