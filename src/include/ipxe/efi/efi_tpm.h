#ifndef _IPXE_EFI_TPM_H
#define _IPXE_EFI_TPM_H

/** @file
 *
 * iPXE TPM API for EFI
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef TPM_EFI
#define TPM_PREFIX_efi
#else
#define TPM_PREFIX_efi __efi_
#endif

#endif /* _IPXE_EFI_TPM_H */
