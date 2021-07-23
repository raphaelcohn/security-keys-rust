#!/usr/bin/env sh
# This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of rust1, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2016 The developers of .cargo. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


set -e
set -u
set -f


exit_error()
{
	local message="$1"
	printf '%s\n' "$message" 1>&2
	exit 1
}

validate_folder_path()
{
	readers_folder_path="$CCID_project_folder_path"/readers
	
	if [ ! -e "$readers_folder_path" ]; then
		exit_error "$readers_folder_path does not exist"
	fi
	if [ ! -d "$readers_folder_path" ]; then
		exit_error "$readers_folder_path is not a valid folder path"
	fi
	if [ ! -r "$readers_folder_path" ]; then
		exit_error "$readers_folder_path is not a readable folder path"
	fi
	if [ ! -x "$readers_folder_path" ]; then
		exit_error "$readers_folder_path is not a searchable folder path"
	fi
}

remove_temporary_folder()
{
	rm -rf "$temporary_folder_path"
}

cross_platform_make_temporary_folder_path()
{
	temporary_folder_path="$(mktemp -d 2>/dev/null || mktemp -d -t 'temporary-folder')"
	if [ -z "$temporary_folder_path" ]; then
		exit_error 'Creating a temporary folder path failed'
	fi
	trap remove_temporary_folder EXIT
}

extract_first_field()
{
	local field_name="$1"
	grep -m 1 '^'"$field_name"': ' "$normalized_txt_file_path" | cut -d' ' -f2- | tr -d '\n'
}

extract_protocols()
{
	local dwProtocols="$(extract_first_field 'dwProtocols')"
	case "$dwProtocols" in
	
		'0x0000 0x0000')
			exit_error "No supported dwProtocols field in $txt_file"
		;;
		
		'0x0000 0x0001')
			printf 'T0'
		;;
		
		'0x0000 0x0002')
			printf 'T1'
		;;
		
		'0x0000 0x0003')
			printf 'T0 | T1'
		;;
		
		*)
			case "$txt_file" in
				
				# Has value 0x0002 0x0003.
				'Identive_Technologies_Multi-ISO_HF_Reader_USB.txt')
					printf 'T0 | T1'
				;;
				
				# Has value 0x0000 0x0300.
				'MySmartPad.txt')
					printf 'T0 | T1'
				;;
				
				*)
					exit_error "Unknown dwProtocols field $dwProtocols in $txt_file"
				;;
				
			esac
		;;
		
	esac
}

extract_mechanical()
{
	local dwMechanical="$(extract_first_field 'dwMechanical')"
	case "$dwMechanical" in
	
		'0x00000000')
			printf 'NoMechanical'
		;;
		
		'0x00000001')
			printf 'Accept'
		;;
		
		'0x00000002')
			printf 'Eject'
		;;
		
		'0x00000003')
			printf 'Eject | Accept'
		;;
		
		'0x00000004')
			printf 'Capture'
		;;
		
		'0x00000005')
			printf 'Capture | Accept'
		;;
		
		'0x00000006')
			printf 'Capture | Eject'
		;;
		
		'0x00000007')
			printf 'Capture | Eject | Accept'
		;;
		
		'0x00000008')
			printf 'LockAndUnlock'
		;;
		
		'0x00000009')
			printf 'LockAndUnlock | Accept'
		;;
		
		'0x0000000A')
			printf 'LockAndUnlock | Eject'
		;;
		
		'0x0000000B')
			printf 'LockAndUnlock | Eject | Accept'
		;;
		
		'0x0000000C')
			printf 'LockAndUnlock | Capture'
		;;
		
		'0x0000000D')
			printf 'LockAndUnlock | Capture | Accept'
		;;
		
		'0x0000000E')
			printf 'LockAndUnlock | Capture | Eject'
		;;
		
		'0x0000000F')
			printf 'LockAndUnlock | Capture | Eject | Accept'
		;;
		
		*)
			case "$txt_file" in
		
				# Has value 0x03000000.
				'MySmartPad.txt')
					printf 'Eject|Accept'
				;;
				
				*)
					exit_error "Unknown dwMechanical field $dwMechanical in $txt_file"
				;;
				
			esac
		;;
	esac
}

extract_maximum_message_length()
{
	extract_first_field 'dwMaxCCIDMessageLength' | cut -d' ' -f1 | tr -d '\n'
}

parse_txt_file()
{
	local normalized_txt_file_path="$temporary_folder_path"/"$txt_file"
	
	case "$txt_file" in
		
		# Contains embedded Carriage Returns (CR)
		'Bit4id_Digital_DNA_Key_v2.txt')
			sed -e 's/^ *//g' "$txt_file" | tr -d '\r' >"$normalized_txt_file_path"
		;;
		
		*)
			sed -e 's/^ *//g' "$txt_file" >"$normalized_txt_file_path"
		;;
		
	esac
	
	
	{
		printf '('
		
		extract_first_field 'idVendor'
		printf ', '
		
		extract_first_field 'idProduct'
		printf ') => entry('
		
		printf '"%s"' "$txt_file"
		printf ', '
		
		printf '"%s"' "$(extract_first_field iManufacturer)"
		printf ', '
		
		printf '"%s"' "$(extract_first_field iProduct)"
		printf ', '
		
		extract_first_field 'bMaxSlotIndex'
		printf ', '
		
		# Composite multi-slot readers, as in `src/ifdhandler.c`, function `IFDHGetCapabilities()` (list defined as if ladder guarded by #define `USE_COMPOSITE_AS_MULTISLOT`).
		case "$txt_file" in
			
			'GemProxDU.txt'|'GemProxSU.txt'|'HID_OMNIKEY_5422.txt')
				printf 'Some(new_non_zero_u8(2))'
			;;
			
			'Feitian_R502.txt')
				printf 'Some(new_non_zero_u8(4))'
			;;
			
			*)
				printf 'None'
			;;
			
		esac
		printf ', '
		
		extract_protocols
		printf ', '
		
		extract_mechanical
		printf ', '

		extract_first_field 'dwFeatures'
		printf ', '

		# The maximum value for dwMaxIFSD is dwMaxCCIDMessageLength - 10; some cards report bogus values.
		# It is 0 for T=0.
		extract_first_field 'dwMaxIFSD'
		printf ', '
		
		# For extended APDU level the value shall be between 261 + 10 (header) and 65544 + 10, otherwise the minimum value is the wMaxPacketSize of the Bulk-OUT endpoint.
		extract_maximum_message_length
		printf '),\n'
	}
}

loop_over_txt_files()
{
	set +f
	local txt_file
	for txt_file in *.txt
	do
		set -f
		if [ ! -e "$txt_file" ]; then
			continue
		fi
		if [ ! -f "$txt_file" ]; then
			continue
		fi
		if [ ! -r "$txt_file" ]; then
			continue
		fi
		if [ ! -s "$txt_file" ]; then
			continue
		fi
		
		if [ "$txt_file" = 'supported_readers.txt' ]; then
			continue
		fi
		
		local file_stem="${txt_file%.*}"
		
		parse_txt_file
	done
	set -f
}

main()
{
	if [ $# -eq 0 ]; then
		local CCID_project_folder_path=/Volumes/Source/other/CCID
	else
		local CCID_project_folder_path="$1"
	fi
	
	local readers_folder_path
	validate_folder_path
	cd "$readers_folder_path" 1>/dev/null 2>/dev/null
	
	cross_platform_make_temporary_folder_path
	
	loop_over_txt_files
}

main "$@"
