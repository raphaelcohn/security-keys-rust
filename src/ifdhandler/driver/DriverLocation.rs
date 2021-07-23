// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Represents a set of locations to search for drivers.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct CcidClassDriverLocation
{
	search_paths: Vec<PathBuf>,
}

impl Default for CcidClassDriverLocation
{
	#[inline(always)]
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
			],
			
			#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "linux", target_os = "macos")))] search_paths: vec!
			[
				PathBuf::from("/usr/local/pcsc/drivers")
			]
		}
	}
}

impl CcidClassDriverLocation
{
	/// Create a new instance.
	#[inline(always)]
	pub fn new(search_path: PathBuf) -> Self
	{
		Self
		{
			search_paths: vec![search_path]
		}
	}
	
	/// Loads drivers in paths like `/usr/libexec/SmartCardServices/drivers` with the following folder structure
	///
	/// ```sh
	/// ifd-ccid.bundle/
	/// 	Contents/
	/// 		Info.plist
	/// 		MacOS/
	/// 			libccid.dylib
	/// ```
	///
	/// Only errors if what seems to be a driver is detected and can not be loaded.
	pub(in crate::ifdhandler) fn load_drivers(&self) -> Result<Vec<Driver>, LoadDriverError>
	{
		let mut drivers = Vec::new();
		self.loop_over_search_path_subfolders(|folder_entry|
		{
			// eg `ifd-ccid.bundle`.
			let file_name = folder_entry.file_name();
			let path: &Path = file_name.as_ref();
			
			if let (Some(file_stem), Some(extension)) = (path.file_stem(), path.extension())
			{
				if extension.as_bytes() == b"bundle"
				{
					// eg `/usr/libexec/SmartCardServices/drivers/ifd-ccid.bundle/Contents`.
					let contents_folder_path = folder_entry.path().append("Contents");
					if contents_folder_path.is_dir()
					{
						// eg `/usr/libexec/SmartCardServices/drivers/ifd-ccid.bundle/Contents/Info.plist`.
						let info_plist_file = contents_folder_path.clone().append("Info.plist");
						if info_plist_file.is_file()
						{
							Self::load_probable_driver(&mut drivers, contents_folder_path, info_plist_file, file_stem)?
						}
					}
				}
			}
			Ok(())
		})?;
		
		Ok(drivers)
	}
	
	fn loop_over_search_path_subfolders(&self, mut use_subfolder_in_search_path: impl FnMut(DirEntry) -> Result<(), LoadDriverError>) -> Result<(), LoadDriverError>
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
								use_subfolder_in_search_path(dir_entry)?
							}
						}
					}
				}
			}
		}
		Ok(())
	}
	
	fn load_probable_driver(drivers: &mut Vec<Driver>, contents_folder_path: PathBuf, info_plist_file: PathBuf, file_stem: &OsStr) -> Result<(), LoadDriverError>
	{
		if let Ok(Value::Dictionary(info_plist)) = Value::from_file(&info_plist_file)
		{
			if let Some(&Value::String(ref string)) = info_plist.get("CFBundleName")
			{
				let is_a_ccid_class_driver = string == "CCIDCLASSDRIVER";
				if is_a_ccid_class_driver
				{
					drivers.push(Driver::load_driver(info_plist, contents_folder_path, file_stem)?);
				}
			}
		}
		Ok(())
	}
}
