#ifndef _IPXE_NULL_TPM_H
#define _IPXE_NULL_TPM_H

/** @file
 *
 * iPXE do-nothing TPM API
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef TPM_NULL
#define TPM_PREFIX_null
#else
#define TPM_PREFIX_null __null_
#endif

#endif /* _IPXE_NULL_TPM_H */
