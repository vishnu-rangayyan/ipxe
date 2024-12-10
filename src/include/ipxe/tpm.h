#ifndef _IPXE_TPM_H
#define _IPXE_TPM_H

/** @file
 *
 * iPXE TPM API
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/api.h>
#include <config/tpm.h>

#define TPM_PCR_IPXE	8U
#define TPM_PCR_KERNEL	8U
#define TPM_PCR_KERNEL_ARGS	9U

/**
 * Calculate static inline TPM API function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define TPM_INLINE( _subsys, _api_func ) \
	SINGLE_API_INLINE ( TPM_PREFIX_ ## _subsys, _api_func )

/**
 * Provide a TPM API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_TPM( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( TPM_PREFIX_ ## _subsys, _api_func, _func )

/**
 * Provide a static inline TPM API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_TPM_INLINE( _subsys, _api_func ) \
	PROVIDE_SINGLE_API_INLINE ( TPM_PREFIX_ ## _subsys, _api_func )

/* Include all architecture-independent TPM API headers */
#include <ipxe/null_tpm.h>
#include <ipxe/efi/efi_tpm.h>

int tpm_init ( void );
void tpm_exit ( void );
int tpm_measure ( uint8_t *buf, uint32_t len, uint32_t pcr, uint8_t *desc );
int tpm_separator ( uint32_t pcr );

#endif /* _IPXE_TPM_H */
