/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_PROCESSING_H
#define PKCS11_TA_PROCESSING_H

#include <pkcs11_attributes.h>
#include <pkcs11_ta.h>
#include <tee_internal_api.h>

struct pkcs11_client;
struct pkcs11_session;
struct pkcs11_object;
struct active_processing;

/**
 * RSA PSS 处理上下文
 *
 * @hash_alg: 哈希算法机制
 * @mgf_type: 掩码生成函数
 * @salt_len: 盐值的长度（字节）
 */
struct rsa_pss_processing_ctx {
	enum pkcs11_mechanism_id hash_alg;
	enum pkcs11_mgf_id mgf_type;
	uint32_t salt_len;
};

/**
 * RSA OAEP 处理上下文
 *
 * @hash_alg: 哈希算法机制
 * @mgf_type: 掩码生成函数
 * @source_type: 源数据类型
 * @source_data_len: 源数据的长度
 * @source_data: 源数据
 */
struct rsa_oaep_processing_ctx {
	enum pkcs11_mechanism_id hash_alg;
	enum pkcs11_mgf_id mgf_type;
	uint32_t source_type;
	uint32_t source_data_len;
	uint8_t source_data[];
};

/**
 * RSA AES 密钥包装处理上下文
 *
 * @hash_alg: 哈希算法机制
 * @mgf_type: 掩码生成函数
 * @aes_key_bits: AES 密钥长度（位）
 * @source_type: 源数据类型
 * @source_data_len: 源数据的长度
 * @source_data: 源数据
 */
struct rsa_aes_key_wrap_processing_ctx {
	enum pkcs11_mechanism_id hash_alg;
	enum pkcs11_mgf_id mgf_type;
	uint32_t aes_key_bits;
	uint32_t source_type;
	uint32_t source_data_len;
	uint8_t source_data[];
};

/**
 * EDDSA 处理上下文
 *
 * @flag: 预哈希标志
 * @ctx_len: 上下文数据的长度
 * @ctx: 上下文数据
 */
struct eddsa_processing_ctx {
	uint32_t flag;
	uint32_t ctx_len;
	uint8_t ctx[];
};

/*
 * 来自 PKCS11 TA 调用命令的入口点
 */

enum pkcs11_rc entry_generate_secret(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_generate_key_pair(struct pkcs11_client *client,
				       uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_processing_init(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params,
				     enum processing_func function);

enum pkcs11_rc entry_processing_step(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params,
				     enum processing_func function,
				     enum processing_step step);

enum pkcs11_rc entry_processing_key(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params,
				    enum processing_func function);

enum pkcs11_rc entry_release_active_processing(struct pkcs11_client *client,
					       uint32_t ptypes,
					       TEE_Param *params);

enum pkcs11_rc entry_wrap_key(struct pkcs11_client *client,
			      uint32_t ptypes, TEE_Param *params);

/*
 * Util
 */
size_t get_object_key_bit_size(struct pkcs11_object *obj);

void release_active_processing(struct pkcs11_session *session);

enum pkcs11_rc alloc_get_tee_attribute_data(TEE_ObjectHandle tee_obj,
					    uint32_t attribute,
					    void **data, size_t *size);

enum pkcs11_rc tee2pkcs_add_attribute(struct obj_attrs **head,
				      uint32_t pkcs11_id,
				      TEE_ObjectHandle tee_obj,
				      uint32_t tee_id);

/* Asymmetric key operations util */
bool processing_is_tee_asymm(uint32_t proc_id);

enum pkcs11_rc init_asymm_operation(struct pkcs11_session *session,
				    enum processing_func function,
				    struct pkcs11_attribute_head *proc_params,
				    struct pkcs11_object *obj);

enum pkcs11_rc step_asymm_operation(struct pkcs11_session *session,
				    enum processing_func function,
				    enum processing_step step,
				    uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc wrap_data_by_asymm_enc(struct pkcs11_session *session,
				      void *data, uint32_t data_sz,
				      void *out_buf, uint32_t *out_sz);

enum pkcs11_rc unwrap_key_by_asymm(struct pkcs11_session *session, void *data,
				   uint32_t data_sz, void **out_buf,
				   uint32_t *out_sz);

/*
 * Symmetric crypto algorithm specific functions
 */
bool processing_is_tee_symm(enum pkcs11_mechanism_id proc_id);

enum pkcs11_rc init_symm_operation(struct pkcs11_session *session,
				   enum processing_func function,
				   struct pkcs11_attribute_head *proc_params,
				   struct pkcs11_object *key);

enum pkcs11_rc step_symm_operation(struct pkcs11_session *session,
				   enum processing_func function,
				   enum processing_step step,
				   uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc tee_init_ctr_operation(struct active_processing *processing,
				      void *proc_params, size_t params_size);

enum pkcs11_rc derive_key_by_symm_enc(struct pkcs11_session *session,
				      void **out_buf, uint32_t *out_sz);

enum pkcs11_rc wrap_data_by_symm_enc(struct pkcs11_session *session,
				     void *data, uint32_t data_sz,
				     void *out_buf, uint32_t *out_sz);

enum pkcs11_rc unwrap_key_by_symm(struct pkcs11_session *session, void *data,
				  uint32_t data_sz, void **out_buf,
				  uint32_t *out_sz);

enum pkcs11_rc tee_ae_decrypt_update(struct pkcs11_session *session,
				     void *in, size_t in_size);

enum pkcs11_rc tee_ae_decrypt_final(struct pkcs11_session *session,
				    void *out, size_t *out_size);

enum pkcs11_rc tee_ae_encrypt_final(struct pkcs11_session *session,
				    void *out, size_t *out_size);

void tee_release_gcm_operation(struct pkcs11_session *session);

enum pkcs11_rc tee_init_gcm_operation(struct pkcs11_session *session,
				      void *proc_params, size_t params_size);

enum pkcs11_rc tee_ae_reinit_gcm_operation(struct pkcs11_session *session);

/* Digest specific functions */
bool processing_is_tee_digest(enum pkcs11_mechanism_id mecha_id);

enum pkcs11_rc
init_digest_operation(struct pkcs11_session *session,
		      struct pkcs11_attribute_head *proc_params);

enum pkcs11_rc step_digest_operation(struct pkcs11_session *session,
				     enum processing_step step,
				     struct pkcs11_object *obj,
				     uint32_t ptypes, TEE_Param *params);

/*
 * Elliptic curve crypto algorithm specific functions
 */
enum pkcs11_rc load_tee_ec_key_attrs(TEE_Attribute **tee_attrs,
				     size_t *tee_count,
				     struct pkcs11_object *obj);

enum pkcs11_rc load_tee_eddsa_key_attrs(TEE_Attribute **tee_attrs,
					size_t *tee_count,
					struct pkcs11_object *obj);

size_t ec_params2tee_keysize(void *attr, size_t size);

uint32_t ec_params2tee_curve(void *attr, size_t size);

enum pkcs11_rc pkcs2tee_algo_ecdsa(uint32_t *tee_id,
				   struct pkcs11_attribute_head *proc_params,
				   struct pkcs11_object *obj);

enum pkcs11_rc generate_ec_keys(struct pkcs11_attribute_head *proc_params,
				struct obj_attrs **pub_head,
				struct obj_attrs **priv_head);

enum pkcs11_rc generate_eddsa_keys(struct pkcs11_attribute_head *proc_params,
				   struct obj_attrs **pub_head,
				   struct obj_attrs **priv_head);

size_t ecdsa_get_input_max_byte_size(TEE_OperationHandle op);

/*
 * RSA crypto algorithm specific functions
 */
enum pkcs11_rc load_tee_rsa_key_attrs(TEE_Attribute **tee_attrs,
				      size_t *tee_count,
				      struct pkcs11_object *obj);

enum pkcs11_rc
pkcs2tee_proc_params_rsa_pss(struct active_processing *proc,
			     struct pkcs11_attribute_head *proc_params);

enum pkcs11_rc pkcs2tee_validate_rsa_pss(struct active_processing *proc,
					 struct pkcs11_object *obj);

enum pkcs11_rc pkcs2tee_algo_rsa_pss(uint32_t *tee_id,
				     struct pkcs11_attribute_head *params);

enum pkcs11_rc
pkcs2tee_proc_params_rsa_oaep(struct active_processing *proc,
			      struct pkcs11_attribute_head *proc_params);

enum pkcs11_rc
pkcs2tee_proc_params_rsa_aes_wrap(struct active_processing *proc,
				  struct pkcs11_attribute_head *proc_params);

enum pkcs11_rc
pkcs2tee_proc_params_eddsa(struct active_processing *proc,
			   struct pkcs11_attribute_head *proc_params);

enum pkcs11_rc pkcs2tee_algo_rsa_oaep(uint32_t *tee_id, uint32_t *tee_hash_id,
				      struct pkcs11_attribute_head *params);

enum pkcs11_rc
pkcs2tee_algo_rsa_aes_wrap(uint32_t *tee_id, uint32_t *tee_hash_id,
			   struct pkcs11_attribute_head *params);

enum pkcs11_rc generate_rsa_keys(struct pkcs11_attribute_head *proc_params,
				 struct obj_attrs **pub_head,
				 struct obj_attrs **priv_head);

size_t rsa_get_input_max_byte_size(TEE_OperationHandle op);

enum pkcs11_rc do_asymm_derivation(struct pkcs11_session *session,
				   struct pkcs11_attribute_head *proc_params,
				   struct obj_attrs **head);

enum pkcs11_rc pkcs2tee_param_ecdh(struct pkcs11_attribute_head *proc_params,
				   void **pub_data, size_t *pub_size);

enum pkcs11_rc pkcs2tee_algo_ecdh(uint32_t *tee_id,
				  struct pkcs11_attribute_head *proc_params,
				  struct pkcs11_object *obj);

enum pkcs11_rc pkcs2tee_rsa_nopad_context(struct active_processing *proc);

#endif /*PKCS11_TA_PROCESSING_H*/
