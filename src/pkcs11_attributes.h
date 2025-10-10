/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_PKCS11_ATTRIBUTES_H
#define PKCS11_TA_PKCS11_ATTRIBUTES_H

#include <inttypes.h>
#include <pkcs11_ta.h>

#include "serializer.h"

/* 对象的密钥校验值（KCV）属性为 3 字节 */
#define PKCS11_CKA_CHECK_VALUE_SIZE	U(3)

struct obj_attrs;
struct pkcs11_object;
struct pkcs11_session;

/*
 * PKCS#11 对象属性指令
 * 带 '*' 的属性是可选的，其他属性必须定义（由调用者提供或使用默认值）。
 *
 * [all] 所有对象：	class（类别）
 *
 * [stored] 存储对象：	persistent（持久性）、need_authen（需要认证）、
 *			modifiable（可修改）、copyable（可复制）、
 *			destroyable（可销毁）、label*（标签）
 *
 * [data] 数据对象：	[all]、[stored]、application_id*（应用ID）、
 *			object_id*（对象ID）、value（值）
 *
 * [key] 密钥对象：	[all]、[stored]、type（类型）、id*（标识）、
 *			start_date/end_date*（起始/结束日期）、
 *			derive（派生）、local（本地）、allowed_mechanisms*（允许的机制）
 *
 * [symm-key] 对称密钥：	[key]、sensitive（敏感）、encrypt（加密）、decrypt（解密）、
 *			sign（签名）、verify（验签）、wrap（包装）、unwrap（解包）、
 *			extractable（可提取）、wrap_with_trusted（可被可信密钥包装）、
 *			trusted（可信）、wrap_template（包装模板）、
 *			unwrap_template（解包模板）、derive_template（派生模板）
 */

/*
 * 在各个处理步骤中检查属性合规性的工具函数
 * 任何处理操作都专属于以下情况之一：
 *
 * 情况1：从本地随机值创建密钥（C_CreateKey 等函数）
 * - 客户端提供属性列表模板，PKCS11 TA 使用默认属性值补全。
 *   如果属性一致且符合令牌/会话状态，则创建对象。
 * - PKCS11 处理序列：
 *   - 检查/设置令牌/会话状态
 *   - 从客户端模板和默认值创建属性列表
 *   - 检查新密钥属性是否符合请求的机制
 *   - 检查新密钥属性是否符合令牌/会话状态
 *   - 为密钥生成值
 *   - 在新密钥中设置一些运行时属性
 *   - 注册新密钥并返回其句柄
 *
 * 情况2：从客户端明文数据创建密钥（C_CreateObject）
 * - 客户端提供属性列表模板，PKCS11 TA 使用默认属性值补全。
 *   如果属性一致且符合令牌/会话状态，则创建对象。
 *   - 检查/设置令牌/会话状态
 *   - 从客户端模板和默认值创建属性列表
 *   - 检查新密钥属性是否符合请求的机制（原始导入）
 *   - 检查新密钥属性是否符合令牌/会话状态
 *   - 在新密钥中设置一些运行时属性
 *   - 注册新密钥并返回其句柄

 * 情况3：使用密钥进行数据处理
 * - 客户端提供机制 ID 和密钥句柄
 * - PKCS11 检查机制和密钥是否符合，机制和令牌/会话状态是否符合，
 *   最后检查密钥和令牌/会话状态是否符合。
 *   - 检查/设置令牌/会话状态
 *   - 检查密钥的父属性是否符合请求的处理
 *   - 检查密钥的父属性是否符合令牌/会话状态
 *   - 检查新密钥属性是否符合密钥的父属性
 *   - 检查新密钥属性是否符合请求的机制
 *   - 检查新密钥属性是否符合令牌/会话状态
 *
 * 情况4：从客户端模板和父密钥创建密钥（例如派生对称密钥）
 * - 客户端参数：新密钥模板、机制 ID、父密钥句柄
 * - PKCS11 基于模板 + 默认值 + 从父密钥属性继承创建新密钥属性列表
 * - PKCS11 检查：
 *   - 令牌/会话状态
 *   - 父密钥 vs 机制
 *   - 父密钥 vs 令牌/会话状态
 *   - 父密钥 vs 新密钥
 *   - 新密钥 vs 机制
 *   - 新密钥 vs 令牌/会话状态
 * - 然后执行处理
 * - 最后完成对象创建
 */

enum processing_func {
	PKCS11_FUNCTION_DIGEST,
	PKCS11_FUNCTION_GENERATE,
	PKCS11_FUNCTION_GENERATE_PAIR,
	PKCS11_FUNCTION_DERIVE,
	PKCS11_FUNCTION_WRAP,
	PKCS11_FUNCTION_UNWRAP,
	PKCS11_FUNCTION_ENCRYPT,
	PKCS11_FUNCTION_DECRYPT,
	PKCS11_FUNCTION_SIGN,
	PKCS11_FUNCTION_VERIFY,
	PKCS11_FUNCTION_SIGN_RECOVER,
	PKCS11_FUNCTION_VERIFY_RECOVER,
	PKCS11_FUNCTION_IMPORT,
	PKCS11_FUNCTION_COPY,
	PKCS11_FUNCTION_MODIFY,
	PKCS11_FUNCTION_DESTROY,
	PKCS11_FUNCTION_UNKNOWN,
};

enum processing_step {
	PKCS11_FUNC_STEP_INIT,
	PKCS11_FUNC_STEP_ONESHOT,
	PKCS11_FUNC_STEP_UPDATE,
	PKCS11_FUNC_STEP_UPDATE_KEY,
	PKCS11_FUNC_STEP_FINAL,
};

/* 为新对象创建属性列表 */
enum pkcs11_rc
create_attributes_from_template(struct obj_attrs **out, void *template,
				size_t template_size, struct obj_attrs *parent,
				enum processing_func func,
				enum pkcs11_mechanism_id proc_mecha,
				enum pkcs11_class_id template_class);

/*
 * 处理前需要执行的各种检查：
 * - 在当前令牌状态下创建新对象
 * - 在处理中使用父对象
 * - 使用提供配置的机制
 */
enum pkcs11_rc check_created_attrs_against_token(struct pkcs11_session *session,
						 struct obj_attrs *head);

enum pkcs11_rc check_created_attrs_against_processing(uint32_t proc_id,
						      struct obj_attrs *head);

enum pkcs11_rc check_created_attrs(struct obj_attrs *key1,
				   struct obj_attrs *key2);

/*
 * 检查处理中使用的父密钥（密钥）的属性是否与目标处理匹配。
 *
 * @proc_id - PKCS11_CKM_xxx
 * @func - 与 @proc_id 一起操作的处理函数的标识符
 * @head - 父对象属性的头部
 */
enum pkcs11_rc
check_parent_attrs_against_processing(enum pkcs11_mechanism_id proc_id,
				      enum processing_func func,
				      struct obj_attrs *head);

enum pkcs11_rc check_access_attrs_against_token(struct pkcs11_session *session,
						struct obj_attrs *head);

enum pkcs11_rc
check_mechanism_against_processing(struct pkcs11_session *session,
				   enum pkcs11_mechanism_id mechanism_type,
				   enum processing_func function,
				   enum processing_step step);

static inline bool attribute_is_hidden(struct pkcs11_attribute_head *req_attr)
{
	return (req_attr->id & PKCS11_CKA_OPTEE_FLAGS_HIDDEN) ==
		PKCS11_CKA_OPTEE_FLAGS_HIDDEN;
}

bool attribute_is_exportable(struct pkcs11_attribute_head *req_attr,
			     struct pkcs11_object *obj);

bool object_is_private(struct obj_attrs *head);

bool object_is_token(struct obj_attrs *head);

bool object_is_modifiable(struct obj_attrs *head);

bool object_is_copyable(struct obj_attrs *head);

/*
 * 检查模板中传递的属性是否可以被修改。这些是 PKCS #11 Cryptographic Token 
 * InterfaceBase Specification Version 2.40 中表 10 标记为 *8,10,11 或 12 的属性。
 * 少数没有此标记但在其表的脚注中明确指定为可修改的属性也被视为可修改
 */
enum pkcs11_rc check_attrs_against_modification(struct pkcs11_session *session,
						struct obj_attrs *head,
						struct pkcs11_object *obj,
						enum processing_func function);

enum pkcs11_rc set_key_data(struct obj_attrs **head, void *data,
			    size_t key_size);

/*
 * 从 @head 获取要包装的密钥数据的分配副本
 * @head: 要查找要包装的密钥数据的对象属性
 * @data: 成功时输出分配并填充的缓冲区
 * @sz: 成功时密钥输出数据大小（字节）
 * 返回符合 pkcs11_rv 的值
 */
enum pkcs11_rc alloc_key_data_to_wrap(struct obj_attrs *head, void **data,
				      uint32_t *sz);

/*
 * 如果缺失，从配对对象添加 CKA_ID 属性。
 *
 * @pub_head - 公钥对象属性
 * @priv_head - 私钥对象属性
 * 返回 PKCS11 返回码
 */
enum pkcs11_rc add_missing_attribute_id(struct obj_attrs **pub_head,
					struct obj_attrs **priv_head);
/*
 * 检查对象的校验值（校验和）
 * @head: 要查找要检查的 KCV 的对象属性
 * 返回符合 pkcs11_rv 的值
 */
enum pkcs11_rc set_check_value_attr(struct obj_attrs **head);

#endif /*PKCS11_TA_PKCS11_ATTRIBUTES_H*/
