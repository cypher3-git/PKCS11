// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

/*
 * ==================================================================================
 * 模块名称: 对象清理与验证 (Object Sanitization)
 * 文件功能: 验证和规范化PKCS#11对象的属性，确保符合规范要求
 * ==================================================================================
 * 
 * 【模块职责】
 * 1. 属性清理：验证和规范化客户端提供的属性模板
 * 2. 类型检查：验证对象类和密钥类型的一致性
 * 3. 默认值：为缺失的属性填充默认值
 * 4. 一致性：检查属性之间的一致性和合法性
 * 5. 序列化：生成符合内部格式的对象属性序列化数据
 * 
 * 【清理流程】
 * 1. 检查必需属性：CKA_CLASS（对象类）
 * 2. 根据对象类检查类型属性：
 *    - 密钥对象: CKA_KEY_TYPE（密钥类型）
 *    - 证书对象: CKA_CERTIFICATE_TYPE（证书类型）
 * 3. 验证属性组合：检查属性之间的合法性
 * 4. 填充默认值：添加规范要求的默认属性
 * 5. 检查属性大小：验证属性值长度是否合法
 * 6. 生成序列化对象：创建内部使用的属性序列化数据
 * 
 * 【对象类型】
 * - CKO_DATA:        数据对象
 * - CKO_CERTIFICATE: 证书对象
 * - CKO_PUBLIC_KEY:  公钥对象
 * - CKO_PRIVATE_KEY: 私钥对象
 * - CKO_SECRET_KEY:  对称密钥对象
 * 
 * 【密钥类型】
 * 对称密钥：
 * - CKK_GENERIC_SECRET: 通用密钥
 * - CKK_AES:            AES密钥
 * - CKK_MD5_HMAC:       HMAC-MD5密钥
 * - CKK_SHA*_HMAC:      HMAC-SHA密钥
 * 
 * 非对称密钥：
 * - CKK_RSA:       RSA密钥
 * - CKK_EC:        椭圆曲线密钥
 * - CKK_EC_EDWARDS: EdDSA密钥
 * 
 * 【属性规则】
 * 每种对象类和密钥类型组合都有特定的：
 * - 必需属性：必须由客户端提供
 * - 可选属性：客户端可选提供
 * - 默认属性：未提供时使用默认值
 * - 禁止属性：不允许该对象类型使用
 * 
 * 【核心函数】
 * - sanitize_client_object(): 清理和验证客户端对象模板
 * - create_attributes_from_template(): 从模板创建属性
 * - sanitize_consistent_class_and_type(): 检查类和类型一致性
 * - set_attributes_default_values(): 设置默认属性值
 * - check_created_attrs(): 验证创建的属性完整性
 * 
 * 【错误检测】
 * - 缺少必需属性
 * - 属性类型不匹配
 * - 属性值大小错误
 * - 属性组合非法
 * - 对象类与密钥类型不一致
 */

#include <assert.h>
#include <bitstring.h>
#include <pkcs11_ta.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <tee_internal_api.h>
#include <trace.h>

#include "attributes.h"
#include "pkcs11_helpers.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "token_capabilities.h"

/*
 * 生成序列化对象的函数集。
 * 引用是指向 struct serializer 的指针。
 */

bool sanitize_consistent_class_and_type(struct obj_attrs *attrs)
{
	switch (get_class(attrs)) {
	case PKCS11_CKO_DATA:
	case PKCS11_CKO_CERTIFICATE:
		return true;
	case PKCS11_CKO_SECRET_KEY:
		return key_type_is_symm_key(get_key_type(attrs));
	case PKCS11_CKO_MECHANISM:
		return mechanism_is_valid(get_mechanism_type(attrs));
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
		return key_type_is_asymm_key(get_key_type(attrs));
	case PKCS11_CKO_OTP_KEY:
	case PKCS11_CKO_DOMAIN_PARAMETERS:
	case PKCS11_CKO_HW_FEATURE:
	default:
		return false;
	}

	return false;
}

static enum pkcs11_rc read_attr_advance(void *buf, size_t blen, size_t *pos,
					struct pkcs11_attribute_head *attr,
					void **data)
{
	uint8_t *b = buf;
	size_t data_pos = 0;
	size_t next_pos = 0;

	if (ADD_OVERFLOW(*pos, sizeof(*attr), &data_pos) || data_pos > blen)
		return PKCS11_CKR_FUNCTION_FAILED;
	TEE_MemMove(attr, b + *pos, sizeof(*attr));

	if (ADD_OVERFLOW(data_pos, attr->size, &next_pos) || next_pos > blen)
		return PKCS11_CKR_FUNCTION_FAILED;

	*data = b + data_pos;
	*pos = next_pos;

	return PKCS11_CKR_OK;
}

/* 清理客户端属性列表中的类别/类型 */
static enum pkcs11_rc sanitize_class_and_type(struct obj_attrs **dst, void *src,
					      size_t src_size,
					      uint32_t class_hint,
					      uint32_t type_hint)
{
	uint32_t class_found = PKCS11_CKO_UNDEFINED_ID;
	size_t pos = sizeof(struct pkcs11_object_head);
	struct pkcs11_attribute_head cli_ref = { };
	uint32_t type_found = PKCS11_UNDEFINED_ID;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	void *data = NULL;

	while (pos != src_size) {
		rc = read_attr_advance(src, src_size, &pos, &cli_ref, &data);
		if (rc)
			goto err;

		if (cli_ref.id == PKCS11_CKA_CLASS) {
			uint32_t class = 0;

			if (cli_ref.size != sizeof(class)) {
				rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
				goto err;
			}

			TEE_MemMove(&class, data, sizeof(class));

			if (class_found != PKCS11_CKO_UNDEFINED_ID &&
			    class_found != class) {
				EMSG("Conflicting class value");
				rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
				goto err;
			}

			class_found = class;
			continue;
		}

		/* 该属性是类中的类型属性 */
		if (pkcs11_attr_is_type(cli_ref.id)) {
			uint32_t type = 0;

			if (cli_ref.size != sizeof(type)) {
				rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
				goto err;
			}

			TEE_MemMove(&type, data, sizeof(type));

			if (type_found != PKCS11_CKK_UNDEFINED_ID &&
			    type_found != type) {
				EMSG("Conflicting type-in-class value");
				rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
				goto err;
			}

			type_found = type;
		}
	}

	if (class_found != PKCS11_CKO_UNDEFINED_ID) {
		rc = add_attribute(dst, PKCS11_CKA_CLASS,
				   &class_found, sizeof(class_found));
		if (rc)
			return rc;
	} else {
		if (class_hint != PKCS11_CKO_UNDEFINED_ID) {
			rc = add_attribute(dst, PKCS11_CKA_CLASS,
					   &class_hint, sizeof(class_hint));
			if (rc)
				return rc;
		}
	}

	if (type_found != PKCS11_UNDEFINED_ID) {
		rc = add_attribute(dst, PKCS11_CKA_KEY_TYPE,
				   &type_found, sizeof(type_found));
		if (rc)
			return rc;
	} else {
		if (type_hint != PKCS11_UNDEFINED_ID) {
			rc = add_attribute(dst, PKCS11_CKA_KEY_TYPE,
					   &type_hint, sizeof(type_hint));
			if (rc)
				return rc;
		}
	}

	return PKCS11_CKR_OK;

err:
	trace_attributes_from_api_head("bad-template", src, src_size);

	return rc;
}

static enum pkcs11_rc sanitize_boolprops(struct obj_attrs **dst, void *src,
					 size_t src_size)
{
	bitstr_t bit_decl(seen_attrs, PKCS11_BOOLPROPS_MAX_COUNT) = { 0 };
	bitstr_t bit_decl(boolprops, PKCS11_BOOLPROPS_MAX_COUNT) = { 0 };
	size_t pos = sizeof(struct pkcs11_object_head);
	struct pkcs11_attribute_head cli_ref = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	bool value = false;
	void *data = NULL;
	int idx = 0;

	/*
	 * We're keeping track of seen boolean attributes in the bitstring
	 * seen_attrs. The bitstring boolprops holds the recorded value
	 * once seen_attrs has been updated.
	 */

	while (pos != src_size) {
		rc = read_attr_advance(src, src_size, &pos, &cli_ref, &data);
		if (rc)
			return rc;

		idx = pkcs11_attr2boolprop_shift(cli_ref.id);
		if (idx < 0)
			continue; /* 跳过非布尔型属性 */

		if (idx >= PKCS11_BOOLPROPS_MAX_COUNT ||
		    cli_ref.size != sizeof(uint8_t))
			return PKCS11_CKR_FUNCTION_FAILED;

		value = *(uint8_t *)data;

		/*
		 * If this attribute has already been seen, check that it
		 * still holds the same value as last time.
		 */
		if (bit_test(seen_attrs, idx) &&
		    value != (bool)bit_test(boolprops, idx))
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;

		if (value)
			bit_set(boolprops, idx);

		if (!bit_test(seen_attrs, idx)) {
			uint8_t pkcs11_bool = value;

			rc = add_attribute(dst, cli_ref.id, &pkcs11_bool,
					   sizeof(pkcs11_bool));
			if (rc)
				return rc;
		}
		bit_set(seen_attrs, idx);
	}

	return PKCS11_CKR_OK;
}

static uint32_t sanitize_indirect_attr(struct obj_attrs **dst,
				       struct pkcs11_attribute_head *cli_ref,
				       char *data)
{
	struct obj_attrs *obj2 = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(pkcs11_attr_has_indirect_attributes(cli_ref->id));

	/* 在清理属性列表的同时构建新的序列化对象 */
	rc = sanitize_client_object(&obj2, data, cli_ref->size,
				    PKCS11_CKO_UNDEFINED_ID,
				    PKCS11_UNDEFINED_ID);
	if (rc)
		goto out;

	rc = add_attribute(dst, cli_ref->id, obj2,
			   sizeof(*obj2) + obj2->attrs_size);
out:
	TEE_Free(obj2);
	return rc;
}

enum pkcs11_rc sanitize_client_object(struct obj_attrs **dst, void *src,
				      size_t size, uint32_t class_hint,
				      uint32_t type_hint)
{
	struct pkcs11_attribute_head cli_ref = { };
	struct pkcs11_object_head head = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	size_t pos = sizeof(head);
	size_t sz_from_hdr = 0;
	void *data = NULL;

	if (size < sizeof(head))
		return PKCS11_CKR_ARGUMENTS_BAD;

	TEE_MemMove(&head, src, sizeof(head));

	if (ADD_OVERFLOW(sizeof(head), head.attrs_size, &sz_from_hdr) ||
	    size < sz_from_hdr)
		return PKCS11_CKR_ARGUMENTS_BAD;

	rc = init_attributes_head(dst);
	if (rc)
		return rc;

	rc = sanitize_class_and_type(dst, src, sz_from_hdr, class_hint,
				     type_hint);
	if (rc)
		return rc;

	rc = sanitize_boolprops(dst, src, sz_from_hdr);
	if (rc)
		return rc;

	while (pos != sz_from_hdr) {
		rc = read_attr_advance(src, sz_from_hdr, &pos, &cli_ref, &data);
		if (rc)
			return rc;

		if (cli_ref.id == PKCS11_CKA_CLASS ||
		    pkcs11_attr_is_type(cli_ref.id) ||
		    pkcs11_attr_is_boolean(cli_ref.id))
			continue;

		if (pkcs11_attr_has_indirect_attributes(cli_ref.id)) {
			rc = sanitize_indirect_attr(dst, &cli_ref, data);
			if (rc)
				return rc;

			continue;
		}

		if (!valid_pkcs11_attribute_id(cli_ref.id, cli_ref.size)) {
			EMSG("Invalid attribute id %#"PRIx32, cli_ref.id);
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}

		rc = add_attribute(dst, cli_ref.id, data, cli_ref.size);
		if (rc)
			return rc;
	}

	return rc;
}

/*
 * Debug: dump object attribute array to output trace
 */

static void __trace_attributes(char *prefix, void *src, void *end)
{
	size_t next = 0;
	char *prefix2 = NULL;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* 在前缀后追加4个空格加上终止符 '\0' */
	prefix2 = TEE_Malloc(prefix_len + 1 + 4, TEE_MALLOC_FILL_ZERO);
	if (!prefix2)
		return;

	TEE_MemMove(prefix2, prefix, prefix_len + 1);
	TEE_MemFill(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 4) = '\0';

	for (; cur < (char *)end; cur += next) {
		struct pkcs11_attribute_head pkcs11_ref;
		uint8_t data[4] = { 0 };
		uint32_t data_u32 = 0;
		char *start = NULL;

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		TEE_MemMove(&data[0], cur + sizeof(pkcs11_ref),
			    MIN(pkcs11_ref.size, sizeof(data)));
		TEE_MemMove(&data_u32, cur + sizeof(pkcs11_ref),
			    sizeof(data_u32));

		next = sizeof(pkcs11_ref) + pkcs11_ref.size;

		DMSG_RAW("%s Attr %s / %s (%#04"PRIx32" %"PRIu32"-byte)",
			 prefix, id2str_attr(pkcs11_ref.id),
			 id2str_attr_value(pkcs11_ref.id, pkcs11_ref.size,
					   cur + sizeof(pkcs11_ref)),
			 pkcs11_ref.id, pkcs11_ref.size);

		switch (pkcs11_ref.size) {
		case 0:
			break;
		case 1:
			DMSG_RAW("%s Attr byte value: %02x", prefix, data[0]);
			break;
		case 2:
			DMSG_RAW("%s Attr byte value: %02x %02x",
				 prefix, data[0], data[1]);
			break;
		case 3:
			DMSG_RAW("%s Attr byte value: %02x %02x %02x",
				 prefix, data[0], data[1], data[2]);
			break;
		case 4:
			DMSG_RAW("%s Attr byte value: %02x %02x %02x %02x",
				 prefix, data[0], data[1], data[2], data[3]);
			break;
		default:
			DMSG_RAW("%s Attr byte value: %02x %02x %02x %02x ...",
				 prefix, data[0], data[1], data[2], data[3]);
			break;
		}

		switch (pkcs11_ref.id) {
		case PKCS11_CKA_WRAP_TEMPLATE:
		case PKCS11_CKA_UNWRAP_TEMPLATE:
		case PKCS11_CKA_DERIVE_TEMPLATE:
			start = cur + sizeof(pkcs11_ref);
			trace_attributes_from_api_head(prefix2, start,
						       (char *)end - start);
			break;
		default:
			break;
		}
	}

	/* 健全性检查 */
	if (cur != (char *)end)
		EMSG("Warning: unexpected alignment issue");

	TEE_Free(prefix2);
}

void trace_attributes_from_api_head(const char *prefix, void *ref, size_t size)
{
	struct pkcs11_object_head head = { };
	char *pre = NULL;
	size_t offset = 0;

	TEE_MemMove(&head, ref, sizeof(head));

	if (size > sizeof(head) + head.attrs_size) {
		EMSG("template overflows client buffer (%zu/%zu)",
		     size, sizeof(head) + head.attrs_size);
		return;
	}

	pre = TEE_Malloc(prefix ? strlen(prefix) + 2 : 2, TEE_MALLOC_FILL_ZERO);
	if (!pre) {
		EMSG("%s: out of memory", prefix);
		return;
	}
	if (prefix)
		TEE_MemMove(pre, prefix, strlen(prefix));

	DMSG_RAW("%s,--- (serial object) Attributes list --------", pre);
	DMSG_RAW("%s| %"PRIu32" item(s) - %"PRIu32" bytes",
		 pre, head.attrs_count, head.attrs_size);

	offset = sizeof(head);
	pre[prefix ? strlen(prefix) : 0] = '|';
	__trace_attributes(pre, (char *)ref + offset,
			   (char *)ref + offset + head.attrs_size);

	DMSG_RAW("%s`-----------------------", prefix ? prefix : "");

	TEE_Free(pre);
}
