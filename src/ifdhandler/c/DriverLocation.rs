// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub struct DriverLocation
{
	search_paths: Vec<PathBuf>,
}

impl Default for DriverLocation
{
	fn default() -> Self
	{
		Self
		{
			#[cfg(any(target_os = "ios", target_os = "macos"))] search_paths: vec!
			[
				// Home brew.
				PathBuf::from("/usr/local/opt/pcsc-lite/lib/pcsc/drivers"),
				
				// Works on Mac OS Mojave.
				PathBuf::from("/usr/libexec/SmartCardServices/drivers"),
				
				// Works on other Mac OS versions.
				PathBuf::from("/usr/local/libexec/SmartCardServices/drivers"),
			],
			
			#[cfg(any(target_os = "android", target_os = "linux"))] search_paths: vec!
			[
				// Alpine Linux.
				PathBuf::from("/usr/lib/pcsc/drivers"),
				
				// Default.
				PathBuf::from("/usr/local/pcsc/drivers"),
			]
		}
	}
}

impl DriverLocation
{
	const KnownBundleName: &'static str = "ifd-ccid.bundle";
	
	/// This is the value of `BUNDLE_HOST` in the CCID project's configuration.
	/// By default, it is `uname | sed -e s,/,_,` except for SunOS and Darwin (instead Solaris and MacOS).
	#[cfg(any(target_os = "ios", target_os = "macos"))] const DriverDirectory: &'static str = "MacOS";
	#[cfg(any(target_os = "android", target_os = "linux"))] const DriverDirectory: &'static str = "Linux";
	#[cfg(target_os = "solaris")] const DriverDirectory: &'static str = "Solaris";
	#[cfg(target_os = "dragonfly")] const DriverDirectory: &'static str = "DragonFly";
	#[cfg(target_os = "freebsd")] const DriverDirectory: &'static str = "FreeBSD";
	#[cfg(target_os = "netbsd")] const DriverDirectory: &'static str = "NetBSD";
	#[cfg(target_os = "openbsd")] const DriverDirectory: &'static str = "OpenBSD";
	
	/// Loads drivers in paths like `/usr/libexec/SmartCardServices/drivers` with the following folder structur
	///
	/// ```sh
	/// ifd-ccid.bundle/
	/// 	Contents/
	/// 		Info.plist
	/// 		MacOS/
	/// 			libccid.dylib
	/// ```
	pub fn load_drivers(&self) -> Result<(), LoadDriverError>
	{
		for search_path in self.search_paths.iter()
		{
			if let Ok(read_dir) = search_path.read_dir()
			{
				for dir_entry in read_dir
				{
					if let Ok(dir_entry) = dir_entry
					{
						if let Ok(file_type) = dir_entry.file_type()
						{
							if file_type.is_dir()
							{
								// eg `ifd-ccid.bundle`.
								let file_name = dir_entry.file_name();
								let path: &Path = file_name.as_ref();
								if let Some(extension) = path.extension()
								{
									if extension.as_bytes() == b"bundle"
									{
										if let Some(file_stem) = path.file_stem()
										{
											if let Ok(our_utf_8_driver_name) = Self::file_stem_to_our_utf_8_driver_name(file_stem)
											{
												// eg `/usr/libexec/SmartCardServices/drivers/ifd-ccid.bundle/Contents`
												let mut contents_folder_path = dir_entry.path().append("Contents");
												if contents_folder_path.is_dir()
												{
													let info_plist_file = contents_folder_path.clone().append("Info.plist");
													if let Ok(Value::Dictionary(dict)) = Value::from_file(&info_plist_file)
													{
														if let Some(&Value::String(ref string)) = dict.get("CFBundleName")
														{
															if string == "CCIDCLASSDRIVER"
															{
																Self::load_driver(dict, contents_folder_path)?;
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		Ok(())
	}
	
	fn file_stem_to_our_utf_8_driver_name(file_stem: &OsStr) -> Result<CString, ()>
	{
		let driver_name_bytes = file_stem.as_bytes();
		let mut vec = Vec::new_with_capacity(driver_name_bytes.len() + 1).map_err(|_| ())?;
		vec.extend_from_slice(driver_name_bytes);
		Ok(CString::new(vec).expect("Should not have embedded NUL bytes"))
	}
	
	fn load_driver(dict: Dictionary, contents_folder_path: PathBuf) -> Result<(u32, Vec<(u16, u16, String)>), LoadDriverError>
	{
		use self::LoadDriverError::*;
		
		let executable_folder_path = contents_folder_path.append(Self::DriverDirectory);
		if !executable_folder_path.is_dir()
		{
			return Err(ExecutableFolderPathDoesNotExist { executable_folder_path })
		}
		
		let library_file_name = Self::get_string(&dict, "CFBundleExecutable", MissingBundleExecutableString)?;
		let x = Self::parse_remaining_info_plist_fields(dict)?;
		
		let library_file_path = executable_folder_path.append(library_file_name);
		if !library_file_path.is_file()
		{
			return Err(LibraryFilePathIsNotAnExtantFile { library_file_path })
		}
		
		let library = unsafe { Library::new(library_file_path)? };
		let IFDHCloseChannel: Symbol<unsafe extern fn(DWORD) -> RESPONSECODE> = Self::get_symbol(&library, b"IFDHCloseChannel\0")?;
		let IFDHControl: Symbol<unsafe extern fn(DWORD, DWORD, *mut u8, DWORD, *mut u8, DWORD, *mut DWORD) -> RESPONSECODE> = Self::get_symbol(&library, b"IFDHControl\0")?;
	}
	
	fn parse_remaining_info_plist_fields(dict: Dictionary) -> Result<(u32, Vec<(u16, u16, String)>), LoadDriverError>
	{
		use self::LoadDriverError::*;
		
		let capabilities = Self::convert_hexadecimal_u32(Self::get_string(&dict, "ifdCapabilities", MissingCapabilitiesString)?, CapabilityIsIsNot10Bytes, CapabilityIsNotHexadecimal)?;
		
		let vendor_identifiers = Self::get_array(&dict, "ifdVendorID", MissingVendorIdentifierArray)?;
		let product_identifiers = Self::get_array(&dict, "ifdVendorID", MissingProductIdentifierArray)?;
		let friendly_names = Self::get_array(&dict, "ifdVendorID", MissingFriendlyNameArray)?;
		
		Self::array_lengths_match(vendor_identifiers, product_identifiers, ProductIdentifiersArrayLengthDiffersToVendorIdentifiersArray)?;
		Self::array_lengths_match(vendor_identifiers, friendly_names, FriendlyNamesArrayLengthDiffersToVendorIdentifiersArray)?;
		
		let length = vendor_identifiers.len();
		let mut vendors = Vec::with_capacity(length);
		for index in 0 .. length
		{
			let vendor_identifier = Self::convert_hexadecimal_u16(Self::get_array_string(vendor_identifiers, index, VendorIdentifierIsNotAString)?, VendorIdentifierStringIsNot6Bytes, VendorIdentifierIsNotHexadecimal)?;
			let product_identifier = Self::convert_hexadecimal_u16(Self::get_array_string(product_identifiers, index, ProductIdentifierIsNotAString)?, ProductIdentifierStringIsNot6Bytes, ProductIdentifierIsNotHexadecimal)?;;
			let friendly_name = Self::get_array_string(friendly_names, index, FriendlyNameIsNotAString)?;
			
			vendors.push((vendor_identifier, product_identifier, friendly_name.to_string()));
		}
		
		Ok((capabilities, vendors))
	}
	
	fn get_string(dict: &Dictionary, key: &str, error: impl FnOnce() -> LoadDriverError) -> Result<&str, LoadDriverError>
	{
		match dict.get(key)
		{
			Some(&Value::String(ref string)) => Ok(string.as_str()),
			
			None => return Err(error()),
		}
	}
	
	fn get_array(dict: &Dictionary, key: &str, error: impl FnOnce() -> LoadDriverError) -> Result<&[Value], LoadDriverError>
	{
		match dict.get(key)
		{
			Some(&Value::Array(ref array)) => Ok(array.as_slice()),
			
			None => return Err(error()),
		}
	}
	
	fn array_lengths_match(array1: &[Value], array2: &[Value], error: impl FnOnce() -> LoadDriverError) -> Result<(), LoadDriverError>
	{
		if likely!(array1.len() == array2.len())
		{
			Ok(())
		}
		else
		{
			Err(error())
		}
	}
	
	fn get_array_string(array: &[Value], index: usize, error: impl FnOnce() -> LoadDriverError) -> Result<&str, LoadDriverError>
	{
		match dict.get(key)
		{
			Some(&Value::String(ref string)) => Ok(string.as_str()),
			
			None => return Err(error()),
		}
	}
	
	fn convert_hexadecimal_u16(value: &str, error_length: LoadDriverError, error_prefix: impl FnOnce(ParseNumberError) -> LoadDriverError) -> Result<u16, LoadDriverError>
	{
		if unlikely!(value.len() != 6)
		{
			return Err(error_length)
		}
		
		let hexadecimal_bytes = value.get_unchecked_range_safe(2 ..);
		u16::parse_hexadecimal_number_upper_or_lower_case_with_0x_prefix(hexadecimal_bytes).map_err(error_prefix)
	}
	
	fn convert_hexadecimal_u32(value: &str, error_length: LoadDriverError, error_prefix: impl FnOnce(ParseNumberError) -> LoadDriverError) -> Result<u32, LoadDriverError>
	{
		if unlikely!(value.len() != 10)
		{
			return Err(error_length)
		}
		
		let hexadecimal_bytes = value.get_unchecked_range_safe(2 ..);
		u32::parse_hexadecimal_number_upper_or_lower_case_with_0x_prefix(hexadecimal_bytes).map_err(error_prefix)
	}
	
	fn get_symbol<'lib, T>(library: &'lib Library, symbol: &'static [u8]) -> Result<Symbol<T>, LoadDriverError>
	{
		let last_index = symbol.len() - 1;
		debug_assert_eq!(symbol.get(last_index), 0x00);
		(unsafe { library.get(b"IFDHCloseChannel\0") }).map_err(|cause| LoadDriverError::GetSymbol { cause, symbol_name: &symbol[ .. last_index] })
	}
}

#[derive(Debug)]
pub(crate) enum LoadDriverError
{
	ExecutableFolderPathDoesNotExist
	{
		executable_folder_path: PathBuf,
	},
	
	MissingBundleExecutableString,
	
	MissingCapabilitiesString,
	
	MissingVendorIdentifierArray,
	
	MissingProductIdentifierArray,
	
	MissingFriendlyNameArray,
	
	ProductIdentifiersArrayLengthDiffersToVendorIdentifiersArray,
	
	FriendlyNamesArrayLengthDiffersToVendorIdentifiersArray,

	CapabilityIsIsNot10Bytes,
	
	CapabilityIsNotHexadecimal(ParseNumberError),

	VendorIdentifierIsNotAString,
	
	ProductIdentifierIsNotAString,
	
	FriendlyNameIsNotAString,
	
	VendorIdentifierStringIsNot6Bytes,
	
	VendorIdentifierIsNotHexadecimal(ParseNumberError),
	
	ProductIdentifierStringIsNot6Bytes,
	
	ProductIdentifierIsNotHexadecimal(ParseNumberError),
	
	LibraryFilePathIsNotAnExtantFile
	{
		library_file_path: PathBuf,
	},
	
	LoadLibrary(libloading::Error),
	
	GetSymbol
	{
		cause: libloading::Error,
	
		symbol_name: &'static [u8],
	},
}

impl From<libloading::Error> for LoadDriverError
{
	#[inline(always)]
	fn from(cause: libloading::Error) -> Self
	{
		LoadDriverError::LoadLibrary(cause)
	}
}

impl Display for LoadDriverError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for LoadDriverError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::LoadDriverError::*;
		
		match self
		{
			CapabilityIsNotHexadecimal(cause) => Some(cause),
			
			VendorIdentifierIsNotHexadecimal(cause) => Some(cause),
			
			ProductIdentifierIsNotHexadecimal(cause) => Some(cause),
			
			LoadLibrary(cause) => Some(cause),
			
			GetSymbol { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}
