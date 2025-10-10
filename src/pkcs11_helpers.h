/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_HELPERS_H
#define PKCS11_HELPERS_H

#include <pkcs11_ta.h>
#include <stdint.h>
#include <stddef.h>
#include <tee_internal_api.h>

#include <pkcs11_attributes.h>
#include <token_capabilities.h>

struct pkcs11_object;

/*
 * TEE 调用参数 #0 为至少 32 位的输入/输出缓冲区，
 * 用于存放 TA 返回的符合 PKCS#11 的返回值。
 */
#define TEE_PARAM0_SIZE_MIN		sizeof(uint32_t)

/* GPD TEE 到 PKCS11 状态转换 */
enum pkcs11_rc tee2pkcs_error(TEE_Result res);

/*
 * 当且仅当属性 ID 与其值大小匹配有效的属性标识符时返回 true。
 *
 * @attribute_id - 目标 PKCS11 属性 ID
 * @size - 属性值的字节数，非定长属性传 0
 */
bool valid_pkcs11_attribute_id(uint32_t attribute_id, uint32_t size);

/*
 * 若 @attribute_id 表示“类型类属性”，返回其字节大小；否则返回 0。
 */
size_t pkcs11_attr_is_type(uint32_t attribute_id);

/* 如果属性具有间接属性，返回 true */
bool pkcs11_attr_has_indirect_attributes(uint32_t attribute_id);

/* 如果对象类与类中类型相关，返回 true */
bool pkcs11_class_has_type(uint32_t class_id);

/* 如果对象类与密钥相关，返回 true */
bool pkcs11_attr_class_is_key(uint32_t class_id);

/* 如果密钥类型 @key_type_id 与对称密钥相关，返回 true */
bool key_type_is_symm_key(uint32_t key_type_id);

/* 如果密钥类型 @key_type_id 与非对称密钥相关，返回 true */
bool key_type_is_asymm_key(uint32_t key_type_id);

/* 如果 @attribute_id 是布尔型，返回 Boolprop 标志位移位置，否则返回 -1 */
int pkcs11_attr2boolprop_shift(uint32_t attribute_id);

/* 将 PKCS11 TA 功能 ID 转换为 TEE 加密操作模式 */
void pkcs2tee_mode(uint32_t *tee_id, enum processing_func function);

/* 从 PKCS11 对象加载 TEE 操作属性，出错时返回 false */
bool pkcs2tee_load_attr(TEE_Attribute *tee_ref, uint32_t tee_id,
			struct pkcs11_object *obj,
			enum pkcs11_attr_id pkcs11_id);

/* 从 PKCS11 对象哈希并加载 TEE 操作属性 */
enum pkcs11_rc pkcs2tee_load_hashed_attr(TEE_Attribute *tee_ref,
					 uint32_t tee_id,
					 struct pkcs11_object *obj,
					 enum pkcs11_attr_id pkcs11_id,
					 uint32_t tee_algo, void *hash_ptr,
					 uint32_t *hash_size);

/* 如果属性是布尔型返回 true，否则返回 false */
static inline bool pkcs11_attr_is_boolean(enum pkcs11_attr_id id)
{
	return pkcs11_attr2boolprop_shift(id) >= 0;
}

#if CFG_TEE_TA_LOG_LEVEL > 0
/* ID 到字符串转换，仅用于跟踪支持 */
const char *id2str_ta_cmd(uint32_t id);
const char *id2str_rc(uint32_t id);
const char *id2str_slot_flag(uint32_t id);
const char *id2str_token_flag(uint32_t id);
const char *id2str_session_flag(uint32_t id);
const char *id2str_session_state(uint32_t id);
const char *id2str_attr(uint32_t id);
const char *id2str_class(uint32_t id);
const char *id2str_type(uint32_t id, uint32_t class);
const char *id2str_key_type(uint32_t id);
const char *id2str_certificate_type(uint32_t id);
const char *id2str_attr_value(uint32_t id, size_t size, void *value);
const char *id2str_proc(uint32_t id);
const char *id2str_function(uint32_t id);

static inline const char *id2str_mechanism(enum pkcs11_mechanism_id id)
{
	return mechanism_string_id(id);
}
#endif /* CFG_TEE_TA_LOG_LEVEL > 0 */
#endif /*PKCS11_HELPERS_H*/
