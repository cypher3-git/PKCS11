// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

/*
 * ==================================================================================
 * 模块名称: 属性管理 (Attributes Management)  
 * 文件功能: PKCS#11对象属性的序列化存储、查询、修改和匹配操作
 * ==================================================================================
 * 
 * 【模块职责】
 * 1. 属性容器管理：创建、扩展、序列化属性列表
 * 2. 属性操作：添加、删除、查询、修改属性
 * 3. 属性匹配：比较属性、模板匹配
 * 4. 调试支持：属性追踪和转储
 * 
 * 【核心数据结构】
 * struct obj_attrs {
 *     uint32_t attrs_size;   // 属性区总字节数
 *     uint32_t attrs_count;  // 属性个数
 *     uint8_t attrs[];       // 连续存储的属性
 * };
 * 
 * 每个属性格式：[id(4B)][size(4B)][data(size B)]
 * 
 * 【内存布局】
 * +----------------+
 * | obj_attrs头    | (8字节)
 * +----------------+
 * | 属性1_id       | (4字节)
 * | 属性1_size     | (4字节)
 * | 属性1_data     | (size字节)
 * +----------------+
 * | 属性2_id       |
 * | 属性2_size     |
 * | 属性2_data     |
 * +----------------+
 * | ...            |
 * 
 * 【关键设计】
 * - 动态扩展：使用TEE_Realloc按需扩展属性列表
 * - 紧凑存储：属性连续存储，无填充
 * - 零拷贝查询：get_attribute_ptr返回指向内部数据的指针
 * - 迭代器模式：支持遍历所有属性
 */

#include <assert.h>
#include <compiler.h>
#include <pkcs11_ta.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <trace.h>
#include <util.h>

#include "attributes.h"
#include "pkcs11_helpers.h"
#include "serializer.h"

/*
 * 初始化属性列表头（分配空属性容器）
 * 
 * @head: 返回分配的属性列表指针
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_DEVICE_MEMORY: 内存不足
 * 
 * 功能：分配并清零8字节的obj_attrs头（attrs_size=0, attrs_count=0）
 * 用途：创建新对象前初始化空属性列表
 */
enum pkcs11_rc init_attributes_head(struct obj_attrs **head)
{
	*head = TEE_Malloc(sizeof(**head), TEE_MALLOC_FILL_ZERO);
	if (!*head)
		return PKCS11_CKR_DEVICE_MEMORY;

	return PKCS11_CKR_OK;
}

/*
 * 向属性列表添加新属性（动态扩展）
 * 
 * @head:      属性列表指针的地址（可能被realloc修改）
 * @attribute: 属性ID（如CKA_CLASS, CKA_VALUE等）
 * @data:      属性值数据
 * @size:      属性值大小
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_DEVICE_MEMORY: 内存不足
 * - PKCS11_CKR_ARGUMENTS_BAD: 溢出
 * 
 * 功能：
 * 1. 扩展属性列表内存
 * 2. 序列化添加：[attribute_id(4B)][size(4B)][data(size B)]
 * 3. 更新attrs_size和attrs_count
 * 
 * 内存管理：
 * - 使用serialize()动态扩展缓冲区
 * - *head可能指向新地址（旧指针失效）
 * - 添加失败时原列表不变
 * 
 * 典型使用：
 *   struct obj_attrs *attrs = NULL;
 *   init_attributes_head(&attrs);
 *   add_attribute(&attrs, CKA_CLASS, &class, sizeof(class));
 *   add_attribute(&attrs, CKA_VALUE, value, value_len);
 */
enum pkcs11_rc add_attribute(struct obj_attrs **head, uint32_t attribute,
			     void *data, size_t size)
{
	size_t buf_len = sizeof(struct obj_attrs) + (*head)->attrs_size;
	char **bstart = (void *)head;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint32_t data32 = 0;

	/* 序列化属性ID */
	data32 = attribute;
	rc = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rc)
		return rc;

	/* 序列化属性大小 */
	data32 = size;
	rc = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rc)
		return rc;

	/* 序列化属性值 */
	rc = serialize(bstart, &buf_len, data, size);
	if (rc)
		return rc;

	/* 更新头部信息（serialize可能改变了head指针） */
	head = (void *)bstart;
	(*head)->attrs_size += 2 * sizeof(uint32_t) + size;
	(*head)->attrs_count++;

	return rc;
}

static enum pkcs11_rc _remove_attribute(struct obj_attrs **head,
					uint32_t attribute, bool empty)
{
	struct obj_attrs *h = *head;
	char *cur = NULL;
	char *end = NULL;
	size_t next_off = 0;

	/* 查找目标属性 */
	cur = (char *)h + sizeof(struct obj_attrs);
	end = cur + h->attrs_size;
	for (; cur < end; cur += next_off) {
		struct pkcs11_attribute_head pkcs11_ref = { };

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		next_off = sizeof(pkcs11_ref) + pkcs11_ref.size;

		if (pkcs11_ref.id != attribute)
			continue;

		if (empty && pkcs11_ref.size)
			return PKCS11_CKR_FUNCTION_FAILED;

		TEE_MemMove(cur, cur + next_off, end - (cur + next_off));

		h->attrs_count--;
		h->attrs_size -= next_off;
		end -= next_off;
		next_off = 0;

		return PKCS11_CKR_OK;
	}

	DMSG("Attribute %s (%#x) not found", id2str_attr(attribute), attribute);
	return PKCS11_RV_NOT_FOUND;
}

enum pkcs11_rc remove_empty_attribute(struct obj_attrs **head,
				      uint32_t attribute)
{
	return _remove_attribute(head, attribute, true /* empty */);
}

void get_attribute_ptrs(struct obj_attrs *head, uint32_t attribute,
			void **attr, uint32_t *attr_size, size_t *count)
{
	char *cur = (char *)head + sizeof(struct obj_attrs);
	char *end = cur + head->attrs_size;
	size_t next_off = 0;
	size_t max_found = *count;
	size_t found = 0;
	void **attr_ptr = attr;
	uint32_t *attr_size_ptr = attr_size;

	for (; cur < end; cur += next_off) {
		/* 对象中 pkcs11_ref 的结构对齐副本 */
		struct pkcs11_attribute_head pkcs11_ref = { };

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		next_off = sizeof(pkcs11_ref) + pkcs11_ref.size;

		if (pkcs11_ref.id != attribute)
			continue;

		found++;

		if (!max_found)
			continue;	/* only count matching attributes */

		if (attr) {
			if (pkcs11_ref.size)
				*attr_ptr++ = cur + sizeof(pkcs11_ref);
			else
				*attr_ptr++ = NULL;
		}

		if (attr_size)
			*attr_size_ptr++ = pkcs11_ref.size;

		if (found == max_found)
			break;
	}

	/* 健全性检查 */
	if (cur > end) {
		DMSG("Exceeding serial object length");
		TEE_Panic(0);
	}

	*count = found;
}

enum pkcs11_rc get_attribute_ptr(struct obj_attrs *head, uint32_t attribute,
				 void **attr_ptr, uint32_t *attr_size)
{
	size_t count = 1;

	get_attribute_ptrs(head, attribute, attr_ptr, attr_size, &count);

	if (!count)
		return PKCS11_RV_NOT_FOUND;

	if (count != 1)
		return PKCS11_CKR_GENERAL_ERROR;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc get_attribute(struct obj_attrs *head, uint32_t attribute,
			     void *attr, uint32_t *attr_size)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	void *attr_ptr = NULL;
	uint32_t size = 0;

	rc = get_attribute_ptr(head, attribute, &attr_ptr, &size);
	if (rc)
		return rc;

	if (attr_size && *attr_size < size) {
		*attr_size = size;
		/* 对于任何大小不匹配的情况，复用 buffer-too-small 错误 */
		return PKCS11_CKR_BUFFER_TOO_SMALL;
	}

	if (attr)
		TEE_MemMove(attr, attr_ptr, size);

	if (attr_size)
		*attr_size = size;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc set_attribute(struct obj_attrs **head, uint32_t attribute,
			     void *data, size_t size)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	rc = _remove_attribute(head, attribute, false);
	if (rc != PKCS11_CKR_OK && rc != PKCS11_RV_NOT_FOUND)
		return rc;

	return add_attribute(head, attribute, data, size);
}

enum pkcs11_rc modify_attributes_list(struct obj_attrs **dst,
				      struct obj_attrs *head)
{
	char *cur = (char *)head + sizeof(struct obj_attrs);
	char *end = cur + head->attrs_size;
	size_t len = 0;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	for (; cur < end; cur += len) {
		struct pkcs11_attribute_head *cli_ref = (void *)cur;
		/* 对象中 pkcs11_ref 的结构对齐副本 */
		struct pkcs11_attribute_head cli_head = { };

		TEE_MemMove(&cli_head, cur, sizeof(cli_head));
		len = sizeof(cli_head) + cli_head.size;

		rc = set_attribute(dst, cli_head.id,
				   cli_head.size ? cli_ref->data : NULL,
				   cli_head.size);
		if (rc)
			return rc;
	}

	return PKCS11_CKR_OK;
}

bool get_bool(struct obj_attrs *head, uint32_t attribute)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint8_t bbool = 0;
	uint32_t size = sizeof(bbool);

	rc = get_attribute(head, attribute, &bbool, &size);

	if (rc == PKCS11_RV_NOT_FOUND)
		return false;

	assert(rc == PKCS11_CKR_OK);
	return bbool;
}

bool attributes_match_reference(struct obj_attrs *candidate,
				struct obj_attrs *ref)
{
	size_t count = ref->attrs_count;
	unsigned char *ref_attr = ref->attrs;
	uint32_t rc = PKCS11_CKR_GENERAL_ERROR;

	if (!ref->attrs_count) {
		DMSG("Empty reference match all");
		return true;
	}

	for (count = 0; count < ref->attrs_count; count++) {
		struct pkcs11_attribute_head pkcs11_ref = { };
		void *value = NULL;
		uint32_t size = 0;

		TEE_MemMove(&pkcs11_ref, ref_attr, sizeof(pkcs11_ref));

		/* 隐藏属性无法匹配 */
		if (attribute_is_hidden(&pkcs11_ref))
			return false;

		rc = get_attribute_ptr(candidate, pkcs11_ref.id, &value, &size);

		if (rc || !value || size != pkcs11_ref.size ||
		    TEE_MemCompare(ref_attr + sizeof(pkcs11_ref), value, size))
			return false;

		ref_attr += sizeof(pkcs11_ref) + pkcs11_ref.size;
	}

	return true;
}

enum pkcs11_rc attributes_match_add_reference(struct obj_attrs **head,
					      struct obj_attrs *ref)
{
	size_t count = ref->attrs_count;
	unsigned char *ref_attr = ref->attrs;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	if (!ref->attrs_count)
		return PKCS11_CKR_OK;

	for (count = 0; count < ref->attrs_count; count++) {
		struct pkcs11_attribute_head pkcs11_ref = { };
		void *value = NULL;
		uint32_t size = 0;

		TEE_MemMove(&pkcs11_ref, ref_attr, sizeof(pkcs11_ref));

		rc = get_attribute_ptr(*head, pkcs11_ref.id, &value, &size);
		if (rc == PKCS11_RV_NOT_FOUND) {
			rc = add_attribute(head, pkcs11_ref.id,
					   ref_attr + sizeof(pkcs11_ref),
					   pkcs11_ref.size);
			if (rc)
				return rc;
		} else {
			if (rc || !value || size != pkcs11_ref.size ||
			    TEE_MemCompare(ref_attr + sizeof(pkcs11_ref), value,
					   size))
				return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}

		ref_attr += sizeof(pkcs11_ref) + pkcs11_ref.size;
	}

	return PKCS11_CKR_OK;
}

#if CFG_TEE_TA_LOG_LEVEL > 0
/*
 * Debug: dump CK attribute array to output trace
 */
#define ATTR_TRACE_FMT	"%s attr %s / %s\t(0x%04"PRIx32" %"PRIu32"-byte"
#define ATTR_FMT_0BYTE	ATTR_TRACE_FMT ")"
#define ATTR_FMT_1BYTE	ATTR_TRACE_FMT ": %02x)"
#define ATTR_FMT_2BYTE	ATTR_TRACE_FMT ": %02x %02x)"
#define ATTR_FMT_3BYTE	ATTR_TRACE_FMT ": %02x %02x %02x)"
#define ATTR_FMT_4BYTE	ATTR_TRACE_FMT ": %02x %02x %02x %02x)"
#define ATTR_FMT_ARRAY	ATTR_TRACE_FMT ": %02x %02x %02x %02x ...)"

static void __trace_attributes(char *prefix, void *src, void *end)
{
	size_t next_off = 0;
	char *prefix2 = NULL;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* append 4 spaces to the prefix plus terminal '\0' */
	prefix2 = TEE_Malloc(prefix_len + 1 + 4, TEE_MALLOC_FILL_ZERO);
	if (!prefix2)
		return;

	TEE_MemMove(prefix2, prefix, prefix_len + 1);
	TEE_MemFill(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 4) = '\0';

	for (; cur < (char *)end; cur += next_off) {
		struct pkcs11_attribute_head pkcs11_ref = { };
		uint8_t data[4] = { 0 };

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		TEE_MemMove(&data[0], cur + sizeof(pkcs11_ref),
			    MIN(pkcs11_ref.size, sizeof(data)));

		next_off = sizeof(pkcs11_ref) + pkcs11_ref.size;

		switch (pkcs11_ref.size) {
		case 0:
			IMSG_RAW(ATTR_FMT_0BYTE,
				 prefix, id2str_attr(pkcs11_ref.id), "*",
				 pkcs11_ref.id, pkcs11_ref.size);
			break;
		case 1:
			IMSG_RAW(ATTR_FMT_1BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size, data[0]);
			break;
		case 2:
			IMSG_RAW(ATTR_FMT_2BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size, data[0],
				 data[1]);
			break;
		case 3:
			IMSG_RAW(ATTR_FMT_3BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size,
				 data[0], data[1], data[2]);
			break;
		case 4:
			IMSG_RAW(ATTR_FMT_4BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size,
				 data[0], data[1], data[2], data[3]);
			break;
		default:
			IMSG_RAW(ATTR_FMT_ARRAY,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size,
				 data[0], data[1], data[2], data[3]);
			break;
		}

		switch (pkcs11_ref.id) {
		case PKCS11_CKA_WRAP_TEMPLATE:
		case PKCS11_CKA_UNWRAP_TEMPLATE:
		case PKCS11_CKA_DERIVE_TEMPLATE:
			if (pkcs11_ref.size)
				trace_attributes(prefix2,
						 cur + sizeof(pkcs11_ref));
			break;
		default:
			break;
		}
	}

	/* 健全性检查 */
	if (cur != end)
		EMSG("Warning: unexpected alignment in object attributes");

	TEE_Free(prefix2);
}

void trace_attributes(const char *prefix, void *ref)
{
	struct obj_attrs head = { };
	char *pre = NULL;

	TEE_MemMove(&head, ref, sizeof(head));

	if (!head.attrs_count)
		return;

	pre = TEE_Malloc(prefix ? strlen(prefix) + 2 : 2, TEE_MALLOC_FILL_ZERO);
	if (!pre) {
		EMSG("%s: out of memory", prefix);
		return;
	}

	if (prefix)
		TEE_MemMove(pre, prefix, strlen(prefix));

	IMSG_RAW("%s,--- (serial object) Attributes list --------", pre);
	IMSG_RAW("%s| %"PRIu32" item(s) - %"PRIu32" bytes",
		 pre, head.attrs_count, head.attrs_size);

	pre[prefix ? strlen(prefix) : 0] = '|';
	__trace_attributes(pre, (char *)ref + sizeof(head),
			   (char *)ref + sizeof(head) + head.attrs_size);

	IMSG_RAW("%s`-----------------------", prefix ? prefix : "");

	TEE_Free(pre);
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
