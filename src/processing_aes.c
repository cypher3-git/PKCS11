// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

/*
 * ==================================================================================
 * 模块名称: AES算法处理 (AES Cryptography Processing)
 * 文件功能: 实现AES-GCM/CCM等认证加密模式的特殊处理
 * ==================================================================================
 * 
 * 【模块职责】
 * 1. AEAD处理：AES-GCM/CCM认证加密/解密
 * 2. AAD管理：关联认证数据(Additional Authenticated Data)处理
 * 3. 安全解密：GCM解密延迟输出（MAC验证通过后才输出明文）
 * 4. 标签处理：认证标签(tag)的生成和验证
 * 
 * 【AEAD模式特点】
 * AES-GCM (Galois/Counter Mode):
 * - 同时提供加密和认证
 * - IV长度通常为12字节
 * - 认证标签长度可配置（4-16字节）
 * - 支持关联数据(AAD)
 * 
 * AES-CCM (Counter with CBC-MAC):
 * - 同时提供加密和认证
 * - Nonce长度7-13字节
 * - 认证标签长度可配置
 * - 支持关联数据(AAD)
 * 
 * 【安全设计】
 * GCM解密安全机制：
 * 根据PKCS#11规范，GCM解密必须在MAC验证通过后才能
 * 向客户端返回明文，防止时序攻击和明文泄露。
 * 
 * 实现方式：
 * 1. Update阶段：解密数据保存在TA内部缓冲区
 * 2. Final阶段：验证MAC后才将明文复制到客户端
 * 3. 验证失败：丢弃所有解密数据，返回错误
 * 
 * 【核心数据结构】
 * struct ae_aes_gcm_ctx {
 *     void *cipher;        // 累积的密文
 *     size_t cipher_size;  // 密文大小
 *     void *clear;         // 解密后的明文（仅解密时）
 *     size_t clear_size;   // 明文大小
 *     bool done;           // 操作是否完成
 * };
 * 
 * 【处理流程】
 * 加密：
 * 1. Init:   设置IV和AAD长度
 * 2. Update: 处理AAD（若有）
 * 3. Update: 加密明文
 * 4. Final:  生成认证标签
 * 
 * 解密（GCM特殊处理）：
 * 1. Init:   设置IV和AAD长度
 * 2. Update: 处理AAD（若有）
 * 3. Update: 解密密文（数据留在TA内）
 * 4. Final:  验证标签，通过后输出明文
 */

#include <assert.h>
#include <compiler.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <util.h>

#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"

/*
 * 认证加密：(AES GCM)
 *
 * 根据PKCS#11规范，GCM解密在解密完成并验证MAC之前不应泄露数据。
 * pkcs11 TA会保留密文数据直到操作完成。因此在AE更新处理期间，
 * 每个解密数据块都保存在分配的缓冲区中，仅在AE完成时当标签
 * 验证通过后才复制到客户端的输出缓冲区。
 *
 * 根据PKCS#11规范，GCM解密期望标签数据通过C_DecryptUpdate()等函数
 * 在输入数据内提供，追加在输入加密数据之后，因此我们不知道哪一次
 * 调用C_DecryptUpdate()是最后一次，其中最后的字节不是密文数据而是
 * 请求的用于消息认证的标签字节。为处理这种情况，TA将最后的输入数据
 * 字节（长度由标签字节大小定义）保存在AE上下文中，等待C_DecryptFinal()
 * 将这些字节作为数据字节或标签/MAC字节处理。参见struct ae_aes_context
 * 中的pending_tag和pending_size。
 */

/*
 * struct out_data_ref - AE解密输出数据块
 * @size - 分配缓冲区的字节大小
 * @data - 指向分配数据的指针
 */
struct out_data_ref {
	size_t size;
	void *data;
};

/*
 * struct ae_aes_context - AE 操作的额外上下文数据
 * @tag_byte_len - 标签大小（字节）
 * @pending_tag - 可能是附加标签的输入数据
 * @pending_size - 可能是标签的待处理输入数据大小
 * @out_data - 指向输出数据引用数组的指针
 * @out_count - out_data 中缓冲区引用的数量
 */
struct ae_aes_context {
	size_t tag_byte_len;
	char *pending_tag;
	size_t pending_size;
	struct out_data_ref *out_data;
	size_t out_count;
};

static enum pkcs11_rc init_ae_aes_context(struct ae_aes_context *ctx)
{
	struct out_data_ref *out_data = NULL;
	char *pending_tag = NULL;

	assert(!ctx->out_data && !ctx->out_count &&
	       !ctx->pending_tag && !ctx->pending_size);

	out_data = TEE_Malloc(sizeof(*out_data), TEE_MALLOC_FILL_ZERO);
	pending_tag = TEE_Malloc(ctx->tag_byte_len, TEE_MALLOC_FILL_ZERO);

	if (!out_data || !pending_tag) {
		TEE_Free(out_data);
		TEE_Free(pending_tag);
		return PKCS11_CKR_DEVICE_MEMORY;
	}

	ctx->pending_tag = pending_tag;
	ctx->out_data = out_data;

	return PKCS11_CKR_OK;
}

static void release_ae_aes_context(struct ae_aes_context *ctx)
{
	size_t n = 0;

	for (n = 0; n < ctx->out_count; n++)
		TEE_Free(ctx->out_data[n].data);

	TEE_Free(ctx->out_data);
	ctx->out_data = NULL;
	ctx->out_count = 0;

	TEE_Free(ctx->pending_tag);
	ctx->pending_tag = NULL;
	ctx->pending_size = 0;
}

/*
 * 此函数向 AE 解密处理提供客户端输入数据。需要考虑 2 个约束。
 *
 * 首先，我们还不知道哪些是密文数据，哪些是标签数据。
 * GP TEE 内部 API 函数要求在调用 TEE_AEDecryptFinal() 时
 * 分离数据和标签。
 *
 * 其次，任何生成的数据都必须保存在 TA 中，只有在标签
 * 成功处理后才能显示。
 */
enum pkcs11_rc tee_ae_decrypt_update(struct pkcs11_session *session,
				     void *in, size_t in_size)
{
	struct ae_aes_context *ctx = session->processing->extra_ctx;
	TEE_Result res = TEE_ERROR_GENERIC;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	size_t data_len = 0;
	size_t ct_size = 0;
	void *ptr = NULL;
	char *ct = NULL;

	if (!in_size)
		return PKCS11_CKR_OK;

	if (!in)
		return PKCS11_CKR_ARGUMENTS_BAD;

	/*
	 * 保存最后的输入字节，以防它们是标签字节
	 * 而不是要解密的密文数据字节。
	 */

	if (ctx->pending_size + in_size <= ctx->tag_byte_len) {
		/*
		 * 数据字节都是潜在的标签字节。
		 * 我们只需要更新 pending_tag 缓冲区，
		 * 不能将任何字节视为数据字节。
		 */
		TEE_MemMove(ctx->pending_tag + ctx->pending_size, in, in_size);

		ctx->pending_size += in_size;

		return PKCS11_CKR_OK;
	}

	/* 待处理和输入数据中非潜在标签的数据大小 */
	data_len = in_size + ctx->pending_size - ctx->tag_byte_len;

	/* 处理有效数据字节的待处理字节 */
	if (ctx->pending_size &&
	    (ctx->pending_size + in_size) >= ctx->tag_byte_len) {
		uint32_t len = MIN(data_len, ctx->pending_size);

		res = TEE_AEUpdate(session->processing->tee_op_handle,
				   ctx->pending_tag, len, NULL, &ct_size);
		if (res && res != TEE_ERROR_SHORT_BUFFER) {
			rc = tee2pkcs_error(res);
			goto out;
		}
		assert(res == TEE_ERROR_SHORT_BUFFER || !ct_size);

		/*
		 * 如果有输出数据要存储（尚未显示），
		 * 使用分配的临时引用重做。
		 */
		if (ct_size) {
			ct = TEE_Malloc(ct_size, TEE_MALLOC_FILL_ZERO);
			if (!ct) {
				rc = PKCS11_CKR_DEVICE_MEMORY;
				goto out;
			}

			res = TEE_AEUpdate(session->processing->tee_op_handle,
					   ctx->pending_tag, len, ct, &ct_size);
			if (res) {
				rc = tee2pkcs_error(res);
				goto out;
			}
			assert(ct_size);
		}

		/* 保存潜在的标签字节供后续使用 */
		TEE_MemMove(ctx->pending_tag, ctx->pending_tag + len,
			    ctx->pending_size - len);

		ctx->pending_size -= len;
		data_len -= len;
	}

	/* 处理非潜在标签字节的输入数据 */
	if (data_len) {
		size_t size = 0;

		res = TEE_AEUpdate(session->processing->tee_op_handle,
				   in, data_len, NULL, &size);
		if (res != TEE_ERROR_SHORT_BUFFER &&
		    (res != TEE_SUCCESS || size)) {
			/* 这是不期望的情况 */
			rc = PKCS11_CKR_GENERAL_ERROR;
			goto out;
		}

		if (size) {
			ptr = TEE_Realloc(ct, ct_size + size);
			if (!ptr) {
				rc = PKCS11_CKR_DEVICE_MEMORY;
				goto out;
			}
			ct = ptr;

			res = TEE_AEUpdate(session->processing->tee_op_handle,
					   in, data_len, ct + ct_size, &size);
			if (res) {
				rc = tee2pkcs_error(res);
				goto out;
			}

			ct_size += size;
		}
	}

	/* 如果有的话，更新上下文中的待处理标签 */
	data_len = in_size - data_len;
	if (data_len > (ctx->tag_byte_len - ctx->pending_size)) {
		/* 这是不期望的情况 */
		rc = PKCS11_CKR_GENERAL_ERROR;
		goto out;
	}

	if (data_len) {
		TEE_MemMove(ctx->pending_tag + ctx->pending_size,
			    (char *)in + in_size - data_len, data_len);

		ctx->pending_size += data_len;
	}

	/* 在上下文中保存输出数据引用 */
	if (ct_size) {
		ptr = TEE_Realloc(ctx->out_data, (ctx->out_count + 1) *
				  sizeof(struct out_data_ref));
		if (!ptr) {
			rc = PKCS11_CKR_DEVICE_MEMORY;
			goto out;
		}
		ctx->out_data = ptr;
		ctx->out_data[ctx->out_count].size = ct_size;
		ctx->out_data[ctx->out_count].data = ct;
		ctx->out_count++;
	}

	rc = PKCS11_CKR_OK;

out:
	if (rc)
		TEE_Free(ct);

	return rc;
}

static enum pkcs11_rc reveal_ae_data(struct ae_aes_context *ctx,
				     void *out, size_t *out_size)
{
	uint32_t req_size = 0;
	char *out_ptr = out;
	size_t n = 0;

	for (req_size = 0, n = 0; n < ctx->out_count; n++)
		req_size += ctx->out_data[n].size;

	if (*out_size < req_size) {
		*out_size = req_size;
		return PKCS11_CKR_BUFFER_TOO_SMALL;
	}

	if (!out_ptr)
		return PKCS11_CKR_ARGUMENTS_BAD;

	for (n = 0; n < ctx->out_count; n++) {
		TEE_MemMove(out_ptr, ctx->out_data[n].data,
			    ctx->out_data[n].size);
		out_ptr += ctx->out_data[n].size;
	}

	release_ae_aes_context(ctx);

	*out_size = req_size;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc tee_ae_decrypt_final(struct pkcs11_session *session,
				    void *out, size_t *out_size)
{
	struct ae_aes_context *ctx = session->processing->extra_ctx;
	TEE_Result res = TEE_ERROR_GENERIC;
	enum pkcs11_rc rc = 0;
	void *data_ptr = NULL;
	size_t data_size = 0;

	if (!out_size) {
		DMSG("Expect at least a buffer for the output data");
		return PKCS11_CKR_ARGUMENTS_BAD;
	}

	/* Final 已经完成，只需要输出数据 */
	if (!ctx->pending_tag)
		return reveal_ae_data(ctx, out, out_size);

	if (ctx->pending_size != ctx->tag_byte_len) {
		DMSG("Not enough samples: %zu/%zu",
		     ctx->pending_size, ctx->tag_byte_len);
		return PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	/* 如果有的话，查询标签大小 */
	data_size = 0;
	res = TEE_AEDecryptFinal(session->processing->tee_op_handle,
				 NULL, 0, NULL, &data_size,
				 ctx->pending_tag, ctx->tag_byte_len);

	if (res == TEE_ERROR_SHORT_BUFFER) {
		data_ptr = TEE_Malloc(data_size, TEE_MALLOC_FILL_ZERO);
		if (!data_ptr) {
			rc = PKCS11_CKR_DEVICE_MEMORY;
			goto out;
		}

		res = TEE_AEDecryptFinal(session->processing->tee_op_handle,
					 NULL, 0, data_ptr, &data_size,
					 ctx->pending_tag, ctx->tag_byte_len);
		assert(res || data_size);
	}

	/* AE 解密已完成 */
	TEE_Free(ctx->pending_tag);
	ctx->pending_tag = NULL;

	rc = tee2pkcs_error(res);
	if (rc)
		goto out;

	if (data_ptr) {
		void *tmp_ptr = NULL;

		tmp_ptr = TEE_Realloc(ctx->out_data, (ctx->out_count + 1) *
				sizeof(struct out_data_ref));
		if (!tmp_ptr) {
			rc = PKCS11_CKR_DEVICE_MEMORY;
			goto out;
		}
		ctx->out_data = tmp_ptr;
		ctx->out_data[ctx->out_count].size = data_size;
		ctx->out_data[ctx->out_count].data = data_ptr;
		ctx->out_count++;

		data_ptr = NULL;
	}

	rc = reveal_ae_data(ctx, out, out_size);

out:
	TEE_Free(data_ptr);

	return rc;
}

enum pkcs11_rc tee_ae_encrypt_final(struct pkcs11_session *session,
				    void *out, size_t *out_size)
{
	struct ae_aes_context *ctx = session->processing->extra_ctx;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *tag = NULL;
	size_t tag_len = 0;
	size_t size = 0;

	if (!out || !out_size)
		return PKCS11_CKR_ARGUMENTS_BAD;

	/* 检查所需大小（警告：2 个输出长度：数据 + 标签）*/
	res = TEE_AEEncryptFinal(session->processing->tee_op_handle,
				 NULL, 0, NULL, &size,
				 &tag, &tag_len);

	if (tag_len != ctx->tag_byte_len ||
	    (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER)) {
		EMSG("Unexpected tag length %zu/%zu or rc 0x%" PRIx32,
		     tag_len, ctx->tag_byte_len, res);
		return PKCS11_CKR_GENERAL_ERROR;
	}

	if (*out_size < size + tag_len) {
		*out_size = size + tag_len;
		return PKCS11_CKR_BUFFER_TOO_SMALL;
	}

	/* 处理数据和标签输入到客户端输出缓冲区 */
	tag = (uint8_t *)out + size;

	res = TEE_AEEncryptFinal(session->processing->tee_op_handle,
				 NULL, 0, out, &size, tag, &tag_len);

	if (tag_len != ctx->tag_byte_len) {
		EMSG("Unexpected tag length");
		return PKCS11_CKR_GENERAL_ERROR;
	}

	if (!res)
		*out_size = size + tag_len;

	return tee2pkcs_error(res);
}

enum pkcs11_rc tee_init_ctr_operation(struct active_processing *processing,
				      void *proc_params, size_t params_size)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	/* CTR 参数 */
	uint32_t incr_counter = 0;
	void *counter_bits = NULL;

	if (!proc_params)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&args, proc_params, params_size);

	rc = serialargs_get(&args, &incr_counter, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&args, &counter_bits, 16);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (incr_counter != 1) {
		DMSG("Supports only 1 bit increment counter: %"PRIu32,
		     incr_counter);

		return PKCS11_CKR_MECHANISM_PARAM_INVALID;
	}

	TEE_CipherInit(processing->tee_op_handle, counter_bits, 16);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc tee_init_gcm_operation(struct pkcs11_session *session,
				      void *proc_params, size_t params_size)
{
	struct ae_aes_context *params = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs args = { };
	/* GCM 参数 */
	uint32_t tag_bitlen = 0;
	uint32_t tag_len = 0;
	uint32_t iv_len = 0;
	void *iv = NULL;
	uint32_t aad_len = 0;
	void *aad = NULL;

	TEE_MemFill(&args, 0, sizeof(args));

	if (!proc_params)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&args, proc_params, params_size);

	rc = serialargs_get(&args, &iv_len, sizeof(uint32_t));
	if (rc)
		goto out;

	rc = serialargs_get_ptr(&args, &iv, iv_len);
	if (rc)
		goto out;

	rc = serialargs_get(&args, &aad_len, sizeof(uint32_t));
	if (rc)
		goto out;

	rc = serialargs_get_ptr(&args, &aad, aad_len);
	if (rc)
		goto out;

	rc = serialargs_get(&args, &tag_bitlen, sizeof(uint32_t));
	if (rc)
		goto out;

	tag_len = ROUNDUP_DIV(tag_bitlen, 8);

	/* 根据 PKCS#11 机制规范 */
	if (tag_bitlen > 128 || !iv_len || iv_len > 256) {
		DMSG("Invalid parameters: tag_bit_len %"PRIu32
		     ", iv_len %"PRIu32, tag_bitlen, iv_len);
		rc = PKCS11_CKR_MECHANISM_PARAM_INVALID;
		goto out;
	}

	params = TEE_Malloc(sizeof(*params), TEE_MALLOC_FILL_ZERO);
	if (!params) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto out;
	}

	/* 存储标签的字节向上舍入字节长度 */
	params->tag_byte_len = tag_len;
	rc = init_ae_aes_context(params);
	if (rc)
		goto out;

	/* 会话处理拥有活动处理参数 */
	assert(!session->processing->extra_ctx);
	session->processing->extra_ctx = params;

	TEE_AEInit(session->processing->tee_op_handle,
		   iv, iv_len, tag_bitlen, 0, 0);

	if (aad_len)
		TEE_AEUpdateAAD(session->processing->tee_op_handle,
				aad, aad_len);

	/*
	 * 保存初始化的操作状态，以便在查询输出缓冲区大小的
	 * 一次性 AE 请求时重置到此状态。
	 */
	TEE_CopyOperation(session->processing->tee_op_handle2,
			  session->processing->tee_op_handle);

	rc = PKCS11_CKR_OK;

out:
	if (rc && params) {
		release_ae_aes_context(params);
		TEE_Free(params);
	}

	return rc;
}

/* 释放与 GCM 处理相关的额外资源 */
void tee_release_gcm_operation(struct pkcs11_session *session)
{
	struct ae_aes_context *ctx = session->processing->extra_ctx;

	release_ae_aes_context(ctx);
	TEE_Free(session->processing->extra_ctx);
	session->processing->extra_ctx = NULL;
}

/* 将处理状态重置为初始化后的状态 */
enum pkcs11_rc tee_ae_reinit_gcm_operation(struct pkcs11_session *session)
{
	struct ae_aes_context *ctx = session->processing->extra_ctx;

	TEE_CopyOperation(session->processing->tee_op_handle,
			  session->processing->tee_op_handle2);

	release_ae_aes_context(ctx);

	return init_ae_aes_context(ctx);
}
