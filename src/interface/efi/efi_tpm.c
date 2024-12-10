/*
 * Copyright (C) 2024 Vishnu Rangayyan <vrangayyan@nvidia.com>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/version.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/TcgService.h>
#include <ipxe/efi/Protocol/Tcg2Protocol.h>
#include <ipxe/tpm.h>


typedef enum tcg_vers {
	TCG_V1=1,
	TCG_V2,
} tcg_vers_t;

enum {
	false=0,
	true=1,
} boolean_t;

static EFI_GUID tcgv1_guid = EFI_TCG_PROTOCOL_GUID;
static EFI_GUID tcgv2_guid = EFI_TCG2_PROTOCOL_GUID;
static tcg_vers_t tcg_ver = 0;
static EFI_HANDLE efitpm_handle;
static void * efitpm_interface = NULL;
static void * tpm_caps = NULL;
static BOOLEAN tpm_available = false;


int efitpm_measure ( uint8_t *buf, uint32_t len, uint32_t pcr, uint8_t *desc) ;
int efitpm_separator ( uint32_t pcr );
int efitpm_init ( void );
void efitpm_exit ( void );

/*
 * efitpm_open - open efi tcg1 or 2 protocol interface, assign efitpm_interface
 */
static EFI_STATUS efitpm_open ( void )
{
	EFI_STATUS efirc;
	EFI_GUID *guid;
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
    UINTN buf_size = sizeof(EFI_HANDLE) * 8;
    uint8_t *buf;
    int ret;

    buf = zalloc ( buf_size );
    if ( ! buf ) {
        ret = -ENOMEM;
        return ret;
    }

    if ( tcg_ver == 0 ) {
		return EFI_INVALID_PARAMETER;
	}
	guid = ( tcg_ver == TCG_V1 ) ? &tcgv1_guid : &tcgv2_guid;

    efirc = bs->LocateHandle ( ByProtocol, &tcgv2_guid, NULL, &buf_size,
                               (EFI_HANDLE *)buf);
    if ( efirc != EFI_SUCCESS ) {
        free (buf);
        return efirc;
    }
    memcpy(&efitpm_handle, buf, sizeof(EFI_HANDLE));
    free (buf);

    efirc = bs->OpenProtocol ( efitpm_handle, guid, &efitpm_interface, efi_image_handle, efitpm_handle,
                               EFI_OPEN_PROTOCOL_GET_PROTOCOL );

	if ( efirc != EFI_SUCCESS ) {
		DBGC ( efitpm_handle, "%s open protocol failed (rc = 0x%x)\n", __FUNCTION__, (unsigned int)efirc );
	}

	return efirc;
}

/*
 * efitpm_close - close efi tcg1 or 2 protocol interface.
 */
static void efitpm_close ( void )
{
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;

	if ( efitpm_interface == NULL || tcg_ver == 0 ) {
		return;
	}
	bs->CloseProtocol ( efitpm_handle,
			    ( tcg_ver == TCG_V1 ) ? &tcgv1_guid : &tcgv2_guid,
			    efi_image_handle, efitpm_handle );
}

/*
 * efitpm_query_v1 - query existence of tpm via tcg v1 interface.
 */
static EFI_STATUS efitpm_query_v1 ( void )
{
	EFI_TCG_PROTOCOL *tpm;
	TCG_EFI_BOOT_SERVICE_CAPABILITY *caps;
	uint32_t flags;
	EFI_PHYSICAL_ADDRESS log_start;
	EFI_PHYSICAL_ADDRESS log_last;
	EFI_STATUS efirc;

	efirc = efitpm_open ( );
	if ( efirc != EFI_SUCCESS ) {
		return efirc;
	}

	caps = zalloc ( sizeof ( TCG_EFI_BOOT_SERVICE_CAPABILITY ) );
	if ( ! caps ) {
		efirc = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	tpm = ( EFI_TCG_PROTOCOL * ) efitpm_interface;
	efirc = tpm->StatusCheck ( tpm, caps, &flags, &log_start, &log_last );
	if ( efirc != EFI_SUCCESS ) {
		DBGC ( tpm, "%s status check failed (rc = 0x%x)\n", __FUNCTION__, (unsigned int)efirc );
		goto done;
	}

	if ( ! caps->TPMPresentFlag || caps->TPMDeactivatedFlag ) {
		DBGC ( tpm, "%s tpm not present or disabled\n", __FUNCTION__ );
		efirc = EFI_NOT_FOUND;
	}
	tpm_caps = ( void * ) caps;
done:
	efitpm_close ( );
	return efirc;
}

/*
 * efitpm_query_v2 - query existence of tpm via tcg v2 interface
 */
static EFI_STATUS efitpm_query_v2 ( void )
{
	EFI_TCG2_PROTOCOL *tpm;
	EFI_TCG2_BOOT_SERVICE_CAPABILITY *caps;
	EFI_STATUS efirc;

    DBGC ( efitpm_interface, "%s: opening tpm handle\n", __FUNCTION__ );
	efirc = efitpm_open ( );
	if ( efirc != EFI_SUCCESS ) {
		DBGC ( efitpm_handle, "%s open protocol failed (rc = 0x%x)\n", __FUNCTION__, (unsigned int)efirc );
		return efirc;
	}

	caps = zalloc ( sizeof ( EFI_TCG2_BOOT_SERVICE_CAPABILITY ) );
	if ( ! caps ) {
		efirc = EFI_OUT_OF_RESOURCES;
		goto done;
	}
    caps->Size = sizeof ( EFI_TCG2_BOOT_SERVICE_CAPABILITY );

    DBGC ( efitpm_interface, "%s: getting tpm capabilities\n", __FUNCTION__ );
	tpm = ( EFI_TCG2_PROTOCOL * ) efitpm_interface;
	efirc = tpm->GetCapability ( tpm, caps );
	if ( efirc != EFI_SUCCESS ) {
		DBGC ( tpm, "%s status check failed (rc = 0x%x), proceeding anyway\n", __FUNCTION__, (unsigned int)efirc );
		efirc = EFI_SUCCESS;
        goto done;
	}

	if ( ! caps->TPMPresentFlag ) {
		DBGC ( tpm, "%s tpm not present or disabled\n", __FUNCTION__ );
		efirc = EFI_NOT_FOUND;
        goto done;
	}
	tpm_caps = ( void * ) caps;
    DBGC ( efitpm_interface, "%s: successfully queried tpm capabilities\n", __FUNCTION__ );

done:
	efitpm_close ( );
	return efirc;
}

static EFI_STATUS efitpm_log_event_v1 ( uint8_t *buf, uint32_t len,
					uint32_t pcr, uint8_t *desc )
{
	EFI_TCG_PROTOCOL *tpm;
	TCG_PCR_EVENT *event;
	uint32_t algo = TPM_ALG_SHA;
	uint32_t event_num;
	EFI_PHYSICAL_ADDRESS last, buf_addr = 0;
	EFI_STATUS efirc;

	event = zalloc ( sizeof ( TCG_PCR_EVENT ) + strlen ( (char *)desc ) + 1 );
	if ( ! event ) {
		return EFI_OUT_OF_RESOURCES;
	}

	/* todo: use builtin */
#if defined (MDE_CPU_IA32) || defined (MDE_CPU_ARM)
	buf_addr = (uint32_t)buf;
#elif defined (MDE_CPU_X64) || defined (MDE_CPU_AARCH64)
	buf_addr = (uint64_t)buf;
#endif
	event->PCRIndex = pcr;
	event->EventType = EV_IPL;
	event->EventSize = strlen ( (char *)desc ) + 1;
	memcpy ( &event->Event[0], desc, event->EventSize );
	efirc = efitpm_open ( );
	if ( efirc != EFI_SUCCESS ) {
		goto done;
	}

	tpm = ( EFI_TCG_PROTOCOL * ) efitpm_interface;
	efirc = tpm->HashLogExtendEvent ( tpm, buf_addr, len, algo, event,
					  &event_num, &last );
	if ( efirc != EFI_SUCCESS ) {
		DBGC ( tpm, "%s failed to extend pcr %u (rc = 0x%x)\n", __FUNCTION__, pcr, (unsigned int)efirc );
	}

done:
	free ( event );
	efitpm_close ( );
	return efirc;
}

static EFI_STATUS efitpm_log_event_v2 ( uint8_t *buf, uint32_t len,
					uint32_t pcr, uint8_t *desc )
{
	EFI_TCG2_PROTOCOL *tpm;
	EFI_TCG2_EVENT *event;
	EFI_STATUS efirc;
	EFI_PHYSICAL_ADDRESS buf_addr = 0;
    uint64_t length = 0;

	event = zalloc ( sizeof ( EFI_TCG2_EVENT ) + strlen ( (char *)desc ) + 1 );
	if ( ! event ) {
		return EFI_OUT_OF_RESOURCES;
	}

	/* todo: use builtin */
#if defined (MDE_CPU_IA32) || defined (MDE_CPU_ARM)
	buf_addr = (uint32_t)buf;
#elif defined (MDE_CPU_X64) || defined (MDE_CPU_AARCH64)
	buf_addr = (uint64_t)buf;
#endif
    length += len;
	event->Header.HeaderSize = sizeof ( EFI_TCG2_EVENT_HEADER );
	event->Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
	event->Header.PCRIndex = pcr;
	event->Header.EventType = EV_IPL;
	event->Size = sizeof ( EFI_TCG2_EVENT ) - sizeof ( event->Event )
		      + strlen ( (char *)desc ) + 1;
	memcpy ( &event->Event[0], desc, strlen ( (char *)desc ) + 1 );
	efirc = efitpm_open ( );
	if ( efirc != EFI_SUCCESS ) {
		goto done;
	}

	tpm = ( EFI_TCG2_PROTOCOL * ) efitpm_interface;
	efirc = tpm->HashLogExtendEvent ( tpm, 0, buf_addr, length, event );
	if ( efirc != EFI_SUCCESS ) {
		DBGC ( tpm, "%s failed to extend pcr %u (rc = 0x%x)\n", __FUNCTION__, pcr, (unsigned int)efirc );
	}

done:
	free ( event );
	efitpm_close ( );
	return efirc;
}

static EFI_STATUS efitpm_log_separator_v1 ( uint32_t pcr )
{
	EFI_TCG_PROTOCOL *tpm;
	TCG_PCR_EVENT *event;
	uint32_t algo = TPM_ALG_SHA;
	uint32_t event_num;
	uint32_t zeroes = 0;
	uint32_t len = 4;
	EFI_PHYSICAL_ADDRESS last, buf_addr = 0;
	EFI_STATUS efirc;

	event = zalloc ( sizeof ( TCG_PCR_EVENT ) + 4 );
	if ( ! event ) {
		return EFI_OUT_OF_RESOURCES;
	}

#if defined (MDE_CPU_IA32)
	buf_addr = (uint32_t)&zeroes;
#elif defined (MDE_CPU_X64)
	buf_addr = (uint64_t)&zeroes;
#endif
	event->PCRIndex = pcr;
	event->EventType = EV_SEPARATOR;
	event->EventSize = 4;
	efirc = efitpm_open ( );
	if ( efirc != EFI_SUCCESS ) {
		goto done;
	}

    DBGC ( efitpm_interface, "%s logging tcg v1 separator for pcr 0x%x\n", __FUNCTION__, pcr );
    tpm = ( EFI_TCG_PROTOCOL * ) efitpm_interface;
	efirc = tpm->HashLogExtendEvent ( tpm, buf_addr, len, algo, event,
					  &event_num, &last );
	if ( efirc != EFI_SUCCESS ) {
		DBGC ( tpm, "%s failed to extend pcr %u (rc = 0x%x)\n", __FUNCTION__, pcr, (unsigned int)efirc );
	}

done:
	free ( event );
	efitpm_close ( );
	return efirc;
}

static EFI_STATUS efitpm_log_separator_v2 ( uint32_t pcr )
{
	EFI_TCG2_PROTOCOL *tpm;
	EFI_TCG2_EVENT *event;
	uint32_t zeroes = 0;
	uint64_t len = 4;
	EFI_STATUS efirc;
	EFI_PHYSICAL_ADDRESS buf_addr = 0;

	event = zalloc ( sizeof ( EFI_TCG2_EVENT ) + 4 );
	if ( ! event ) {
		return EFI_OUT_OF_RESOURCES;
	}

#if defined (MDE_CPU_IA32)
	buf_addr = (uint32_t)&zeroes;
#elif defined (MDE_CPU_X64)
	buf_addr = (uint64_t)&zeroes;
#endif
	event->Header.HeaderSize = sizeof ( EFI_TCG2_EVENT_HEADER );
	event->Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
	event->Header.PCRIndex = pcr;
	event->Header.EventType = EV_SEPARATOR;
	event->Size = sizeof ( EFI_TCG2_EVENT ) - sizeof ( event->Event ) + 4;

	efirc = efitpm_open ( );
	if ( efirc != EFI_SUCCESS ) {
		goto done;
	}

    DBGC ( efitpm_interface, "%s logging tcg v2 separator for pcr 0x%x", __FUNCTION__, pcr );
	tpm = ( EFI_TCG2_PROTOCOL * ) efitpm_interface;
	efirc = tpm->HashLogExtendEvent ( tpm, 0, buf_addr, len, event );
	if ( efirc != EFI_SUCCESS ) {
		DBGC ( tpm, "%s failed to extend pcr 0x%x (rc = 0x%x)\n", __FUNCTION__, pcr, (unsigned int)efirc );
	}

done:
	free ( event );
	efitpm_close ( );
	return efirc;
}

int efitpm_measure ( uint8_t *buf, uint32_t len, uint32_t pcr,
			   uint8_t *desc )
{
	EFI_STATUS efirc = EFI_INVALID_PARAMETER;

	if ( tpm_available == false ) {
        DBGC ( efitpm_interface, "%s tpm is not available\n", __FUNCTION__ );
		return 0;
	}

	if ( tcg_ver == TCG_V1 ) {
        DBGC ( efitpm_interface, "%s logging tcg v1 event for %p, len 0x%x, to pcr 0x%x for %s\n", __FUNCTION__, buf, len, pcr, desc );
		efirc = efitpm_log_event_v1 ( buf, len, pcr, desc );
	} else if ( tcg_ver == TCG_V2 ) {
        DBGC ( efitpm_interface, "%s logging tcg v2 event for %p, len 0x%x, to pcr 0x%x for %s\n", __FUNCTION__, buf, len, pcr, desc );
		efirc = efitpm_log_event_v2 ( buf, len, pcr, desc );
	}
	if ( efirc != EFI_SUCCESS ) {
		DBGC ( efitpm_interface, "%s failed to measure into pcr 0x%x (rc = 0x%x)\n", __FUNCTION__, pcr, (unsigned int)efirc );
	}

	return 0;
}

int efitpm_separator ( uint32_t pcr )
{
	EFI_STATUS efirc = EFI_INVALID_PARAMETER;

	if ( tpm_available == false ) {
		return 0;
	}
	if ( tcg_ver == TCG_V1 ) {
		efirc = efitpm_log_separator_v1 ( pcr );
	} else if ( tcg_ver == TCG_V2 ) {
		efirc = efitpm_log_separator_v2 ( pcr );
	}
	if ( efirc != EFI_SUCCESS ) {
		DBGC ( efitpm_interface, "%s failed to log separator into pcr 0x%x (rc = 0x%x)\n", __FUNCTION__, pcr, (unsigned int)efirc );
	}

	return 0;
}

/*
 * efitpm_init - initialize uefi tcg v1/v2 interface to the tpm, probe the tpm.
 */
int efitpm_init ( void )
{
	UINTN buf_size = sizeof(EFI_HANDLE) * 8;
	uint8_t *buf;
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_STATUS efirc;
	int ret;

	buf = zalloc ( buf_size );
	if ( ! buf ) {
		ret = -ENOMEM;
		return ret;
	}
    DBGC ( efitpm_interface, "%s: searching for tpm tcg v2 efi handle\n", __FUNCTION__ );
    efirc = bs->LocateHandle ( ByProtocol, &tcgv2_guid, NULL, &buf_size,
                               (EFI_HANDLE *)buf);
    if ( efirc == EFI_SUCCESS ) {
        DBGC ( efitpm_interface, "%s: found tpm tcg v2 efi handle, querying it\n", __FUNCTION__ );
        memcpy ( &efitpm_handle, buf, sizeof( EFI_HANDLE ) );
        tcg_ver = TCG_V2;
        efirc = efitpm_query_v2 ( );
        if ( efirc == EFI_SUCCESS ) {
            DBGC ( efitpm_interface, "%s: queried tpm tcg v2 efi handle successfully\n", __FUNCTION__ );
            tpm_available = true;
            free(buf);
            return 0;
        } else {
            DBGC ( efitpm_interface, "%s: failed to query tpm tcg v2 efi handle, 0x%x\n", __FUNCTION__, efirc );
        }
    }

    DBGC ( efitpm_interface, "%s: searching for tpm tcg v1 efi handle\n", __FUNCTION__ );
    efirc = bs->LocateHandle ( ByProtocol, &tcgv1_guid, NULL, &buf_size,
				   (EFI_HANDLE *)buf );
	if ( efirc == EFI_SUCCESS ) {
        DBGC ( efitpm_interface, "%s: found tpm tcg v1 efi handle, querying it\n", __FUNCTION__ );
		memcpy ( &efitpm_handle, buf, sizeof( EFI_HANDLE ) );
		tcg_ver = TCG_V1;
		efirc = efitpm_query_v1 ( );
		if ( efirc == EFI_SUCCESS ) {
            DBGC(efitpm_interface, "%s: queried tpm tcg v1 efi handle successfully\n", __FUNCTION__);
            tpm_available = true;
        }
	}
	free ( buf );

	/* tcg tpm interface not available is not an error */
	return 0;
}

void efitpm_exit ( void )
{
	if ( tpm_caps ) {
		free ( tpm_caps );
	}
}

PROVIDE_TPM ( efi, tpm_init, efitpm_init );
PROVIDE_TPM ( efi, tpm_exit, efitpm_exit );
PROVIDE_TPM ( efi, tpm_measure, efitpm_measure );
PROVIDE_TPM ( efi, tpm_separator, efitpm_separator );
