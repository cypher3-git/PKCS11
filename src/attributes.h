/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

/*
 * ==================================================================================
 * 模块接口定义: 属性管理 (Attributes Management)
 * ==================================================================================
 * 
 * 本头文件定义PKCS#11对象属性的数据结构和操作接口。
 * 
 * 【核心功能】
 * 1. 属性容器：序列化存储对象的所有属性
 * 2. 属性操作：添加、删除、查询、修改属性
 * 3. 属性匹配：比较属性列表、查找对象
 * 4. 布尔属性优化：常用布尔属性使用位图快速访问
 * 
 * 【关键数据结构】
 * - obj_attrs: 序列化的属性列表容器
 * - boolprop_attr: 布尔属性索引枚举（用于位图）
 * 
 * 【设计特点】
 * - 动态扩展：属性列表按需扩展
 * - 紧凑存储：属性连续存储，无浪费
 * - 快速访问：常用布尔属性用64位掩码缓存
 */

#ifndef PKCS11_TA_ATTRIBUTES_H
#define PKCS11_TA_ATTRIBUTES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

#include "pkcs11_helpers.h"

/*
 * 布尔属性位映射（Boolean Property Attributes）
 * 
 * 性能优化：
 * 某些布尔属性（如CKA_TOKEN, CKA_PRIVATE等）访问频繁，
 * 将它们映射到64位掩码中，避免每次都遍历属性列表查找。
 * 
 * 使用方式：
 * - 对象创建时，从属性列表中提取布尔属性到64位掩码
 * - 快速检查：(bitmask & (1ULL << BPA_TOKEN)) != 0
 * - 最多支持64个布尔属性
 */
#define PKCS11_BOOLPROPS_BASE		0
#define PKCS11_BOOLPROPS_MAX_COUNT	64

/*
 * 布尔属性索引枚举
 * 
 * 每个枚举值对应64位掩码中的一个位位置。
 * 命名规则：BPA_xxx 对应 PKCS#11的 CKA_xxx 属性
 * 
 * 例如：
 * - BPA_TOKEN对应CKA_TOKEN（对象是否持久化）
 * - BPA_PRIVATE对应CKA_PRIVATE（对象是否私有）
 * - BPA_ENCRYPT对应CKA_ENCRYPT（密钥是否可加密）
 */
enum boolprop_attr {
	BPA_TOKEN = 0,              /* 对象存储到令牌（持久化） */
	BPA_PRIVATE,                /* 对象需要登录才能访问 */
	BPA_TRUSTED,                /* 对象是受信任的 */
	BPA_SENSITIVE,              /* 敏感密钥（不可导出） */
	BPA_ENCRYPT,                /* 密钥可用于加密 */
	BPA_DECRYPT,                /* 密钥可用于解密 */
	BPA_WRAP,                   /* 密钥可包装其他密钥 */
	BPA_UNWRAP,                 /* 密钥可解包装其他密钥 */
	BPA_SIGN,                   /* 密钥可用于签名 */
	BPA_SIGN_RECOVER,           /* 密钥可用于签名恢复 */
	BPA_VERIFY,                 /* 密钥可用于验签 */
	BPA_VERIFY_RECOVER,         /* 密钥可用于验签恢复 */
	BPA_DERIVE,                 /* 密钥可用于派生 */
	BPA_EXTRACTABLE,            /* 密钥可被导出 */
	BPA_LOCAL,                  /* 密钥在本地生成 */
	BPA_NEVER_EXTRACTABLE,      /* 密钥从未可导出 */
	BPA_ALWAYS_SENSITIVE,       /* 密钥始终敏感 */
	BPA_MODIFIABLE,             /* 对象可被修改 */
	BPA_COPYABLE,               /* 对象可被复制 */
	BPA_DESTROYABLE,            /* 对象可被销毁 */
	BPA_ALWAYS_AUTHENTICATE,    /* 每次使用都需认证 */
	BPA_WRAP_WITH_TRUSTED,      /* 仅可用受信密钥包装 */
};

/*
 * 序列化属性列表的头部结构
 * 
 * 内存布局：
 * +------------------+
 * | attrs_size (4B)  |  属性区总字节数
 * | attrs_count (4B) |  属性个数
 * +------------------+
 * | 属性1[id|size|data] |
 * | 属性2[id|size|data] |
 * | ...              |
 * +------------------+
 * 
 * @attrs_size:  attrs[]数组的总字节数（不含头部8字节）
 * @attrs_count: 属性个数
 * @attrs:       柔性数组，存储连续的属性数据
 * 
 * 每个属性格式：
 * [id: uint32_t][size: uint32_t][data: uint8_t[size]]
 */
struct obj_attrs {
	uint32_t attrs_size;   /* 属性区总字节数 */
	uint32_t attrs_count;  /* 属性个数 */
	uint8_t attrs[];       /* 柔性数组：属性数据 */
};

/*
 * init_attributes_head() - 为序列化属性分配引用
 * @head:	*@head 保存获取到的指针
 *
 * 获取到的指针可以通过简单的 TEE_Free(reference) 来释放。
 *
 * 成功时返回 PKCS11_CKR_OK，失败时返回 PKCS11 返回码。
 */
enum pkcs11_rc init_attributes_head(struct obj_attrs **head);

/*
 * add_attribute() - 更新序列化属性以添加条目
 *
 * @head:	*@head 指向序列化属性，
 *		添加属性时可能会重新分配
 * @attribute:	要添加的属性 ID
 * @data:	属性的不透明数据
 * @size:	数据大小
 *
 * 成功时返回 PKCS11_CKR_OK，失败时返回 PKCS11 返回码。
 */
enum pkcs11_rc add_attribute(struct obj_attrs **head, uint32_t attribute,
			     void *data, size_t size);

/*
 * 更新序列化属性以移除空条目。可能会重新定位属性列表缓冲区。
 * 只期望条目的 1 个实例。
 *
 * 成功时返回 PKCS11_CKR_OK，失败时返回 PKCS11 返回码。
 */
enum pkcs11_rc remove_empty_attribute(struct obj_attrs **head, uint32_t attrib);

/*
 * get_attribute_ptrs() - 获取具有给定 ID 的属性指针
 * @head:	指向序列化属性的指针
 * @attribute:	要查找的属性 ID
 * @attr:	指向 @head 内部数据的指针数组
 * @attr_size:	保存 @attr 指向的每个值大小的 uint32_t 数组
 * @count:	上述数组中的元素数量
 *
 * 如果 *count == 0，计数并在 *count 中返回与输入属性 ID 匹配的属性数量。
 *
 * 如果 *count != 0，返回找到的属性的地址和大小，最多到出现次数 *count。
 * attr 和 attr_size 预期足够大。attr 是找到的值的输出数组。attr_size 
 * 是找到的每个值大小的输出数组。
 *
 * 如果 attr_size != NULL，在 *attr_size 中返回属性值大小。
 * 如果 attr != NULL，在 *attr 中返回属性值的地址。
 */
void get_attribute_ptrs(struct obj_attrs *head, uint32_t attribute,
			void **attr, uint32_t *attr_size, size_t *count);

/*
 * get_attribute_ptr() - 获取给定 ID 属性的指针
 * @head:	指向序列化属性的指针
 * @attribute:	属性 ID
 * @attr:	*@attr 保存获取到的属性值指针
 * @attr_size:	属性值的大小
 *
 * 如果未找到匹配的属性，返回 PKCS11_RV_NOT_FOUND。
 * 如果 attr_size != NULL，在 *attr_size 中返回属性值大小。
 * 如果 attr != NULL，在 *attr 中返回属性值的地址。
 *
 * 成功时返回 PKCS11_CKR_OK 或 PKCS11_RV_NOT_FOUND，失败时返回 PKCS11 返回码。
 */
enum pkcs11_rc get_attribute_ptr(struct obj_attrs *head, uint32_t attribute,
				 void **attr_ptr, uint32_t *attr_size);

/*
 * get_attribute() - 复制出给定 ID 的属性
 * @head:	指向序列化属性的指针
 * @attribute:	要查找的属性 ID
 * @attr:	保存获取到的属性值
 * @attr_size:	属性值的大小
 *
 * 如果未找到属性，返回 PKCS11_RV_NOT_FOUND。
 *
 * 如果 attr_size != NULL，检查 attr 是否有足够的空间存储值（与 *attr_size 
 * 比较），将属性值复制到 attr，最后在 *attr_size 中返回实际值大小。
 *
 * 如果空间不足，返回 PKCS11_CKR_BUFFER_TOO_SMALL，并在 *attr_size 中返回
 * 期望的大小。
 *
 * 如果 attr 为 NULL 且 attr_size != NULL，在 *attr_size 中返回期望的缓冲区大小。
 *
 * 成功时返回 PKCS11_CKR_OK 或 PKCS11_RV_NOT_FOUND，失败时返回 PKCS11 返回码。
 */
enum pkcs11_rc get_attribute(struct obj_attrs *head, uint32_t attribute,
			     void *attr, uint32_t *attr_size);

/*
 * set_attribute() - 设置给定 ID 属性的值
 * @head:	指向要设置属性的序列化属性的指针，
 *		修改/添加属性时可能会重新定位
 * @attribute:	要查找的属性 ID
 * @data:	保存要设置的属性值
 * @size:	属性值的大小
 *
 * 成功时返回 PKCS11_CKR_OK，失败时返回 PKCS11 返回码。
 */
enum pkcs11_rc set_attribute(struct obj_attrs **head, uint32_t attribute,
			     void *data, size_t size);

/*
 * modify_attributes_list() - 根据源属性列表中的属性值修改目标属性列表
 * （序列化属性）中的属性值
 * @dst:	指向要修改属性的序列化属性的指针，
 *		修改属性时可能会重新定位
 * @head:	包含需要在目标属性列表中修改的属性的序列化属性
 *
 * 成功时返回 PKCS11_CKR_OK
 */
enum pkcs11_rc modify_attributes_list(struct obj_attrs **dst,
				      struct obj_attrs *head);

/*
 * get_u32_attribute() - 复制出给定 ID 的 32 位属性值
 * @head:	指向序列化属性的指针
 * @attribute:	属性 ID
 * @attr:	保存获取到的 32 位属性值
 *
 * 如果未找到属性，返回 PKCS11_RV_NOT_FOUND。
 * 如果获取到的属性值不是 4 字节大小，返回 PKCS11_CKR_GENERAL_ERROR。
 *
 * 成功时返回 PKCS11_CKR_OK 或 PKCS11_RV_NOT_FOUND，失败时返回 PKCS11 返回码。
 */

static inline enum pkcs11_rc get_u32_attribute(struct obj_attrs *head,
					       uint32_t attribute,
					       uint32_t *attr)
{
	uint32_t size = sizeof(uint32_t);
	enum pkcs11_rc rc = get_attribute(head, attribute, attr, &size);

	if (!rc && size != sizeof(uint32_t))
		return PKCS11_CKR_GENERAL_ERROR;

	return rc;
}

/*
 * 如果参考属性列表中的所有属性在候选属性列表中都找到且值匹配，
 * 则返回 true。
 */
bool attributes_match_reference(struct obj_attrs *ref,
				struct obj_attrs *candidate);

/*
 * 检查 @ref 中的属性是否都在 @head 中找到或添加
 *
 * 成功时返回 PKCS11_CKR_OK，失败时返回 PKCS11 返回码。
 */
enum pkcs11_rc attributes_match_add_reference(struct obj_attrs **head,
					      struct obj_attrs *ref);
/*
 * get_class() - 获取对象的类 ID
 * @head:	指向序列化属性的指针
 *
 * 成功时返回对象的类 ID，出错时返回 PKCS11_CKO_UNDEFINED_ID。
 */
static inline enum pkcs11_class_id get_class(struct obj_attrs *head)
{
	uint32_t class = 0;
	uint32_t size = sizeof(class);

	if (get_attribute(head, PKCS11_CKA_CLASS, &class, &size))
		return PKCS11_CKO_UNDEFINED_ID;

	return class;
}

/*
 * get_key_type() - 获取对象的密钥类型
 * @head:	指向序列化属性的指针
 *
 * 成功时返回对象的密钥类型，出错时返回 PKCS11_CKK_UNDEFINED_ID。
 */
static inline enum pkcs11_key_type get_key_type(struct obj_attrs *head)
{
	uint32_t type = 0;
	uint32_t size = sizeof(type);

	if (get_attribute(head, PKCS11_CKA_KEY_TYPE, &type, &size))
		return PKCS11_CKK_UNDEFINED_ID;

	return type;
}

/*
 * get_certificate_type() - 获取对象的证书类型
 * @head:	指向序列化属性的指针
 *
 * 成功时返回对象的证书类型，出错时返回 PKCS11_CKC_UNDEFINED_ID。
 */
static inline
enum pkcs11_certificate_type get_certificate_type(struct obj_attrs *head)
{
	uint32_t type = 0;

	if (get_u32_attribute(head, PKCS11_CKA_CERTIFICATE_TYPE, &type))
		return PKCS11_CKC_UNDEFINED_ID;

	return type;
}

/*
 * get_mechanism_type() - 获取对象的机制类型
 * @head:	指向序列化属性的指针
 *
 * 成功时返回对象的机制类型，出错时返回 PKCS11_CKM_UNDEFINED_ID。
 */
static inline enum pkcs11_mechanism_id get_mechanism_type(struct obj_attrs *head)
{
	uint32_t type = 0;
	uint32_t size = sizeof(type);

	if (get_attribute(head, PKCS11_CKA_MECHANISM_TYPE, &type, &size))
		return PKCS11_CKM_UNDEFINED_ID;

	return type;
}

/*
 * get_bool() - 获取属性的布尔值
 * @head:	指向序列化属性的指针
 * @attribute:	要查找的属性 ID
 *
 * 如果属性 ID 不是布尔类型，可能会断言失败。
 *
 * 如果找到，返回提供的属性 ID 的布尔值，否则返回 false。
 */
bool get_bool(struct obj_attrs *head, uint32_t attribute);

#if CFG_TEE_TA_LOG_LEVEL > 0
/* 调试：将对象属性转储到 IMSG() 跟踪控制台 */
void trace_attributes(const char *prefix, void *ref);
#else
static inline void trace_attributes(const char *prefix __unused,
				    void *ref __unused)
{
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
#endif /*PKCS11_TA_ATTRIBUTES_H*/
