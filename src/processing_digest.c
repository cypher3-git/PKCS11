// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Vaisala Oyj
 */

/*
 * ==================================================================================
 * 模块名称: 摘要算法处理 (Digest Processing)
 * 文件功能: 实现PKCS#11消息摘要操作（C_Digest*命令）
 * ==================================================================================
 * 
 * 【模块职责】
 * 1. 摘要计算：MD5, SHA-1/224/256/384/512
 * 2. 密钥摘要：C_DigestKey（将密钥值输入摘要）
 * 3. 多步处理：Init -> Update -> Final
 * 4. 单步处理：DigestSingle（一次性完成）
 * 5. TEE集成：调用TEE Crypto API实现摘要
 * 
 * 【支持的机制】
 * - PKCS11_CKM_MD5:      MD5摘要
 * - PKCS11_CKM_SHA_1:    SHA-1摘要
 * - PKCS11_CKM_SHA224:   SHA-224摘要
 * - PKCS11_CKM_SHA256:   SHA-256摘要
 * - PKCS11_CKM_SHA384:   SHA-384摘要
 * - PKCS11_CKM_SHA512:   SHA-512摘要
 * 
 * 【处理流程】
 * 多步处理：
 * 1. C_DigestInit(mechanism)      → init_digest_operation()
 * 2. C_DigestUpdate(data) [多次]  → step_digest_operation(UPDATE)
 * 3. C_DigestKey(key) [可选]      → step_digest_operation(UPDATE_KEY)
 * 4. C_DigestFinal() / C_Digest() → step_digest_operation(FINAL/ONESHOT)
 * 
 * 【核心函数】
 * - init_digest_operation():  初始化摘要操作
 * - step_digest_operation():  执行摘要步骤
 * - processing_is_tee_digest(): 检查是否为TEE摘要机制
 * - pkcs2tee_algorithm_digest(): PKCS#11机制转TEE算法
 * 
 * 【TEE操作】
 * - TEE_AllocateOperation(): 分配摘要操作句柄
 * - TEE_DigestUpdate():      更新摘要数据
 * - TEE_DigestDoFinal():     完成摘要计算
 */

#include <assert.h>
#include <config.h>
#include <pkcs11_ta.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>
#include <util.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"

bool processing_is_tee_digest(enum pkcs11_mechanism_id mecha_id)
{
	switch (mecha_id) {
	case PKCS11_CKM_MD5:
	case PKCS11_CKM_SHA_1:
	case PKCS11_CKM_SHA224:
	case PKCS11_CKM_SHA256:
	case PKCS11_CKM_SHA384:
	case PKCS11_CKM_SHA512:
		return true;
	default:
		return false;
	}
}

static enum pkcs11_rc
pkcs2tee_algorithm(uint32_t *tee_id, struct pkcs11_attribute_head *proc_params)
{
	static const struct {
		enum pkcs11_mechanism_id mech_id;
		uint32_t tee_id;
	} pkcs2tee_algo[] = {
		{ PKCS11_CKM_MD5, TEE_ALG_MD5 },
		{ PKCS11_CKM_SHA_1, TEE_ALG_SHA1 },
		{ PKCS11_CKM_SHA224, TEE_ALG_SHA224 },
		{ PKCS11_CKM_SHA256, TEE_ALG_SHA256 },
		{ PKCS11_CKM_SHA384, TEE_ALG_SHA384 },
		{ PKCS11_CKM_SHA512, TEE_ALG_SHA512 },
	};
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(pkcs2tee_algo); n++) {
		if (proc_params->id == pkcs2tee_algo[n].mech_id) {
			*tee_id = pkcs2tee_algo[n].tee_id;
			return PKCS11_CKR_OK;
		}
	}

	return PKCS11_RV_NOT_IMPLEMENTED;
}

static enum pkcs11_rc
allocate_tee_operation(struct pkcs11_session *session,
		       struct pkcs11_attribute_head *params)
{
	uint32_t algo = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(session->processing->tee_op_handle == TEE_HANDLE_NULL);

	if (pkcs2tee_algorithm(&algo, params))
		return PKCS11_CKR_FUNCTION_FAILED;

	res = TEE_AllocateOperation(&session->processing->tee_op_handle,
				    algo, TEE_MODE_DIGEST, 0);
	if (res)
		EMSG("TEE_AllocateOp. failed %#"PRIx32, algo);

	if (res == TEE_ERROR_NOT_SUPPORTED)
		return PKCS11_CKR_MECHANISM_INVALID;

	return tee2pkcs_error(res);
}

enum pkcs11_rc init_digest_operation(struct pkcs11_session *session,
				     struct pkcs11_attribute_head *proc_params)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	assert(processing_is_tee_digest(proc_params->id));

	rc = allocate_tee_operation(session, proc_params);
	if (!rc)
		session->processing->mecha_type = proc_params->id;

	return rc;
}

/*
 * step_digest_operation - processing digest operation step
 *
 * @session - current session
 * @step - step ID in the processing (oneshot, update, final)
 * @obj - PKCS#11 object for key based operations
 * @ptype - invocation parameter types
 * @params - invocation parameter references
 */
enum pkcs11_rc step_digest_operation(struct pkcs11_session *session,
				     enum processing_step step,
				     struct pkcs11_object *obj,
				     uint32_t ptypes, TEE_Param *params)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	void *in_buf = NULL;
	size_t in_size = 0;
	void *out_buf = NULL;
	size_t out_size = 0;
	void *secret_value = NULL;
	uint32_t secret_value_size = 0;
	enum pkcs11_key_type key_type = PKCS11_CKK_UNDEFINED_ID;
	struct active_processing *proc = session->processing;

	if (TEE_PARAM_TYPE_GET(ptypes, 1) == TEE_PARAM_TYPE_MEMREF_INPUT) {
		in_buf = params[1].memref.buffer;
		in_size = params[1].memref.size;
		if (in_size && !in_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 2) == TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		out_buf = params[2].memref.buffer;
		out_size = params[2].memref.size;
		if (out_size && !out_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 3) != TEE_PARAM_TYPE_NONE)
		return PKCS11_CKR_ARGUMENTS_BAD;

	switch (step) {
	case PKCS11_FUNC_STEP_ONESHOT:
	case PKCS11_FUNC_STEP_UPDATE:
	case PKCS11_FUNC_STEP_UPDATE_KEY:
	case PKCS11_FUNC_STEP_FINAL:
		break;
	default:
		TEE_Panic(step);
		break;
	}

	assert(proc->tee_op_handle != TEE_HANDLE_NULL);

	assert(processing_is_tee_digest(proc->mecha_type));

	/*
	 * Feed active operation with data
	 */

	switch (step) {
	case PKCS11_FUNC_STEP_UPDATE_KEY:
		assert(obj);

		if (!IS_ENABLED(CFG_PKCS11_TA_ALLOW_DIGEST_KEY))
			return PKCS11_CKR_KEY_INDIGESTIBLE;

		if (get_class(obj->attributes) != PKCS11_CKO_SECRET_KEY)
			return PKCS11_CKR_KEY_INDIGESTIBLE;

		key_type = get_key_type(obj->attributes);

		if (key_type != PKCS11_CKK_GENERIC_SECRET &&
		    key_type != PKCS11_CKK_AES)
			return PKCS11_CKR_KEY_INDIGESTIBLE;

		rc = get_attribute_ptr(obj->attributes, PKCS11_CKA_VALUE,
				       &secret_value, &secret_value_size);
		assert(!rc && secret_value && secret_value_size);

		TEE_DigestUpdate(proc->tee_op_handle, secret_value,
				 secret_value_size);
		return PKCS11_CKR_OK;

	case PKCS11_FUNC_STEP_UPDATE:
		if (!in_buf || !in_size)
			return PKCS11_CKR_OK;

		TEE_DigestUpdate(proc->tee_op_handle, in_buf, in_size);
		return PKCS11_CKR_OK;

	case PKCS11_FUNC_STEP_ONESHOT:
		if (!out_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;

		goto do_final;

	case PKCS11_FUNC_STEP_FINAL:
		if (in_buf || !out_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;

		goto do_final;

	default:
		TEE_Panic(step);
		break;
	}

do_final:
	res = TEE_DigestDoFinal(proc->tee_op_handle,
				in_buf, in_size, out_buf,
				&out_size);
	rc = tee2pkcs_error(res);

	if (rc == PKCS11_CKR_OK || rc == PKCS11_CKR_BUFFER_TOO_SMALL)
		params[2].memref.size = out_size;

	return rc;
}
