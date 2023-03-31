#ifndef ISV_ENCLAVE_U_H__
#define ISV_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"
#include "stdio.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t put_secret_data(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac);
sgx_status_t enclave_encrypt(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_data, uint32_t secret_size, uint8_t* out_data, uint8_t* out_mac);
sgx_status_t enclave_decrypt(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_data, uint32_t secret_size, uint8_t* out_data, uint8_t* in_mac);
sgx_status_t enclave_ecc_init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_private_t* p_private, sgx_ec256_public_t* p_public, sgx_ecc_state_handle_t* ecc_handle);
sgx_status_t enclave_ecc_sign(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_data, uint32_t data_size, sgx_ec256_private_t* p_private, sgx_ec256_signature_t* p_signature, uint8_t* ecc_handle);
sgx_status_t enclave_ecc_verify(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_data, uint32_t data_size, sgx_ec256_public_t* p_public, sgx_ec256_signature_t* p_signature, uint8_t* p_result, uint8_t* ecc_handle);
sgx_status_t enclave_use(sgx_enclave_id_t eid);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
