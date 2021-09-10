// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// This is the 'NTDDI' version'; see <https://docs.microsoft.com/en-us/windows/win32/winprog/using-the-windows-headers?redirectedfrom=MSDN>.
/// eg 0x06030000 for Windows 8.1 (codenamed Windows Blue).
#[derive(Default, Copy, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[repr(transparent)]
pub struct WindowsVersion(u32);

impl WindowsVersion
{
	#[inline(always)]
	fn parse(dwWindowsVersion: u32) -> Result<Self, MicrosoftOperatingSystemPlatformDeviceCapabilityParseError>
	{
		const Windows81: u32 = 0x06030000;
		if unlikely!(dwWindowsVersion < Windows81)
		{
			return Err(MicrosoftOperatingSystemPlatformDeviceCapabilityParseError::VersionLessThanWindows81 { dwWindowsVersion })
		}
		Ok(Self(dwWindowsVersion))
	}
}
