#ifndef CONFIG_TPM_H
#define CONFIG_TPM_H

/** @file
 *
 * TPM configuration
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <config/defaults.h>

/*
 * TPM external interfaces
 *
 */
//#undef	TPM_EFI		/* Provide EFI TPM 1.2 and 2.0 interface */

#include <config/named.h>
#include NAMED_CONFIG(tpm.h)
#include <config/local/tpm.h>
#include LOCAL_NAMED_CONFIG(tpm.h)

#endif /* CONFIG_TPM_H */
