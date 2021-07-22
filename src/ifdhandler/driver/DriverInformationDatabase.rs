// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


struct DriverInformationDatabase(HashMap<OurDriverName, (DriverInfoPListValidater, FixedDriverCapabilities)>);

impl DriverInformationDatabase
{
	#[inline(always)]
	fn validate_info_plist<'a>(&'a self, our_driver_name: &CStr, info_plist: &Dictionary) -> Result<&'a FixedDriverCapabilities, LoadDriverError>
	{
		match self.0.get(our_driver_name)
		{
			None => Ok(FixedDriverCapabilities::unknown()),
			
			Some((check, fixed_driver_capabilities)) =>
			{
				(*check)(info_plist).map_err(LoadDriverError::AdditionalInfoPListCheckFailed)?;
				Ok(fixed_driver_capabilities)
			}
		}
	}
	
	#[inline(always)]
	fn default() -> &'static Self
	{
		static X: SyncLazy<DriverInformationDatabase> = SyncLazy::new(||
		{
			let mut checks: DriverInformationDatabase = DriverInformationDatabase(HashMap::with_capacity(1));
			checks.ifd_ccid();
			checks
		});
		
		&X
	}
	
	#[inline(always)]
	fn ifd_ccid(&mut self)
	{
		let our_driver_name = our_driver_name_ifd_ccid();
		let _ = self.0.insert(our_driver_name, (validate_info_plist_ifd_ccid, fixed_driver_capabilities_ifd_ccid()));
	}
}

