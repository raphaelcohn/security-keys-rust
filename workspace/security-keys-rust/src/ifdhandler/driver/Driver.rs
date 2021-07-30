// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone)]
pub(in crate::ifdhandler) struct Driver
{
	our_driver_name: OurDriverName,
	
	details: DriverDetails,
	
	fixed_driver_capabilities: &'static FixedDriverCapabilities,
	
	functions: DriverFunctions,
}

impl Driver
{
	// TAG_IFD_SIMULTANEOUS_ACCESS: Could we use this with a Rust equivalent of Java's java.util.concurrent.Semaphore? It is effectively the number of instances of a driver.
	// TAG_IFD_THREAD_SAFE true unless mac os. What does it mean?
	// TAG_IFD_SLOT_THREAD_SAFE: slot access is thread safe in a multi-slot card reader, ie we don't need to lock for a slot.
		// Always false; would only be true for a very small number of CCID USB devices in any event (bMaxCCIDBusySlots).
		/*
  bMaxCCIDBusySlots: 0   - clearly bogus data.
  bMaxCCIDBusySlots: 1
  bMaxCCIDBusySlots: 1
  bMaxCCIDBusySlots: 1
  bMaxCCIDBusySlots: 2
  bMaxCCIDBusySlots: 5
  bMaxCCIDBusySlots: 8
		 */
	// TAG_IFD_SLOTS_NUMBER: How many slots a card reader has (composite or not)
	
	// TODO: Consider reading the code for parse.c and making use of it.
	
	#[inline(always)]
	pub(in crate::ifdhandler) fn create_channel_using_ignored_channel_identifier(&self, logical_unit_number: LogicalUnitNumber) -> Result<(), GenericError<CreateChannelUnexpectedError>>
	{
		let response_code = self.functions.IFDHCreateChannel(logical_unit_number.into_DWORD(), DriverFunctions::IgnoredChannel);
		Self::process_create_channel_response_code(response_code)
	}
	
	#[inline(always)]
	pub(in crate::ifdhandler) fn create_channel_using_name(&self, logical_unit_number: LogicalUnitNumber, device_name: &CStr) -> Result<(), GenericError<CreateChannelUnexpectedError>>
	{
		let response_code = self.functions.IFDHCreateChannelByName(logical_unit_number.into_DWORD(), device_name.as_ptr());
		Self::process_create_channel_response_code(response_code)
	}
	
	#[inline(always)]
	fn process_create_channel_response_code(response_code: RESPONSECODE) -> Result<(), GenericError<CreateChannelUnexpectedError>>
	{
		if likely!(response_code == IFD_SUCCESS)
		{
			return Ok(())
		}
		
		use GenericError::*;
		
		let error = match response_code
		{
			// eg for ifd-ccid, no more reader indices; defined by CCID_DRIVER_MAX_READERS, which is 16 or could not open USB device.
			IFD_COMMUNICATION_ERROR => Communication,
			
			// There is no card reader for the device name.
			IFD_NO_SUCH_DEVICE => NoSuchDevice,
			
			_ => Unexpected(CreateChannelUnexpectedError::parse(response_code))
		};
		Err(error)
	}
	
	/// Use this in preference to `get_capability(SCARD_ATTR_ICC_INTERFACE_STATUS)` and `get_capability(SCARD_ATTR_ICC_PRESENCE)`.
	#[inline(always)]
	pub(in crate::ifdhandler) fn presence(&self, logical_unit_number: LogicalUnitNumber) -> Result<bool, GenericError<PresenceUnexpectedError>>
	{
		use GenericError::*;
		
		match self.functions.IFDHICCPresence(logical_unit_number.into_DWORD())
		{
			IFD_ICC_PRESENT => Ok(true),
			
			IFD_ICC_NOT_PRESENT => Ok(false),
			
			// eg for ifd-ccid, no more reader indices; defined by CCID_DRIVER_MAX_READERS, which is 16 or could not open USB device.
			IFD_COMMUNICATION_ERROR => Err(Communication),
			
			// There is no card reader for the device name.
			IFD_NO_SUCH_DEVICE => Err(NoSuchDevice),
			
			response_code @ _ => Err(Unexpected(PresenceUnexpectedError::parse(response_code))),
		}
	}
	
	/*
		get_capability()
			maps to IFDGetCapabilities()
				takes a lock on rContext pthread_mutex_lock(rContext->mMutex)
					inheritated from 'parent' reader context
					set to NULL if the 'parent' reader has TAG_IFD_THREAD_SAFE - this is horrible, as this 'capability tag' is access via a Lun, even though it has nothing to do with a Lun.
					parent may be the same reader, or the same reader with a different slot.
				what is pMutex for - it seems to be count of the number of shared uses of the mMutex
				maps to IFDHGetCapabilities(Lun)
		
		TAG_IFD_SIMULTANEOUS_ACCESS
			Always CCID_DRIVER_MAX_READERS for ifd ccid
		
		TAG_IFD_SLOT_THREAD_SAFE
			- used for initialization of a mutex if a card has multiple slots
			- called on the actual reader context, not the paret; see line 433 onwards in readerfactory.c for implications if a card reader is a multiple-slot reader (result is greater than 1).
			- always false for ifd-ccid, so really difficult to test for other cards.
		
		Multiple slot card readers
			- create as normal, then initialize more than once.
	 */
	
	fn load_driver(info_plist: Dictionary, contents_folder_path: PathBuf, file_stem: &OsStr) -> Result<Driver, LoadDriverError>
	{
		let library_file_path = Self::library_file_path(&info_plist, contents_folder_path)?;
		let details = DriverDetails::parse_remaining_info_plist_fields(&info_plist)?;
		let our_driver_name = Self::file_stem_to_our_driver_name(file_stem)?;
		let driver_information_database = DriverInformationDatabase::default();
		let fixed_driver_capabilities = driver_information_database.validate_info_plist(&our_driver_name, &info_plist)?;
		let functions = DriverFunctions::load(library_file_path)?;
		
		Ok
		(
			Self
			{
				our_driver_name,
			
				details,
				
				fixed_driver_capabilities,
				
				functions,
			}
		)
	}
	
	#[inline(always)]
	fn library_file_path(info_plist: &Dictionary, contents_folder_path: PathBuf) -> Result<PathBuf, LoadDriverError>
	{
		use LoadDriverError::*;
		
		let library_file_path =
		{
			let executable_folder_path = Self::append_driver_folder_name(contents_folder_path);
			if !executable_folder_path.is_dir()
			{
				return Err(ExecutableFolderPathDoesNotExist { executable_folder_path })
			}
			let library_file_name = dictionary_get_string(&info_plist, "CFBundleExecutable", MissingBundleExecutableString)?;
			executable_folder_path.append(library_file_name)
		};
		
		if likely!(library_file_path.is_file())
		{
			Ok(library_file_path)
		}
		else
		{
			Err(LibraryFilePathIsNotAnExtantFile { library_file_path })
		}
	}
	
	#[inline(always)]
	fn file_stem_to_our_driver_name(file_stem: &OsStr) -> Result<OurDriverName, LoadDriverError>
	{
		let driver_name_bytes = file_stem.as_bytes();
		let mut vec = Vec::new_with_capacity(driver_name_bytes.len() + 1).map_err(LoadDriverError::CouldNotAllocateMemoryForOurDriverName)?;
		vec.extend_from_slice(driver_name_bytes);
		Ok(CString::new(vec).expect("Should not have embedded NUL bytes"))
	}
	
	/// This is the value of `BUNDLE_HOST` in the CCID project's configuration.
	/// By default, it is `uname | sed -e s,/,_,` except for SunOS and Darwin (which instead are Solaris and MacOS, respectively).
	#[inline(always)]
	fn append_driver_folder_name(contents_folder_path: PathBuf) -> PathBuf
	{
		static DriverFolderName: SyncLazy<&'static OsStr> = SyncLazy::new(||
		{
			static mut uts_name: MaybeUninit<utsname> = MaybeUninit::uninit();
			
			let result = unsafe { uname(uts_name.as_mut_ptr()) };
			if likely!(result == 0)
			{
				let initialized_uts_name = unsafe { uts_name.assume_init_ref() };
				let sys_name = unsafe { CStr::from_bytes_with_nul_unchecked(transmute(&initialized_uts_name.sysname[..])) };
				
				static Darwin: &'static CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"Darwin\0") };
				static SunOS: &'static CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"SunOS\0") };
				let bundle_host = if likely!(sys_name == Darwin)
				{
					static MacOS: &'static [u8] = b"MacOs";
					MacOS
				}
				else if unlikely!(sys_name == SunOS)
				{
					static Solaris: &'static [u8] = b"Solaris";
					Solaris
				}
				else
				{
					sys_name.to_bytes()
				};
				OsStr::from_bytes(bundle_host)
			}
			else if likely!(result == -1)
			{
				let error_number = errno();
				match error_number.0
				{
					EFAULT => unreachable!("Should never get EFAULT from our call to utsname()"),
					
					_ => unreachable!("Unexpected error {} from utsname()", error_number)
				}
			}
			else
			{
				unreachable!("Unexpected result {} from utsname()", result);
			}
		});
		
		contents_folder_path.append(*DriverFolderName.deref())
	}
}
