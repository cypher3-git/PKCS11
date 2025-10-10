/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_OBJECT_H
#define PKCS11_TA_OBJECT_H

#include <pkcs11_ta.h>
#include <sys/queue.h>
#include <tee_internal_api.h>

struct ck_token;
struct obj_attrs;
struct pkcs11_client;
struct pkcs11_session;

/*
 * PKCS#11 对象结构
 * 
 * @link: 对象在双向链表中的引用
 * @attributes: 指向序列化对象属性的指针
 * @key_handle: 如果在操作中使用，则为 GPD TEE 对象句柄
 * @key_type: GPD TEE 密钥类型（用于处理的快捷方式）
 * @token: 对象关联的令牌
 * @uuid: 如果是持久对象，则为持久数据库中的对象 UUID，否则为 NULL
 * @attribs_hdl: 如果是持久对象，则为 GPD TEE 属性句柄
 */
struct pkcs11_object {
	LIST_ENTRY(pkcs11_object) link;
	struct obj_attrs *attributes;
	TEE_ObjectHandle key_handle;
	uint32_t key_type;
	struct ck_token *token;
	TEE_UUID *uuid;
	TEE_ObjectHandle attribs_hdl;
};

LIST_HEAD(object_list, pkcs11_object);

struct pkcs11_object *pkcs11_handle2object(uint32_t client_handle,
					   struct pkcs11_session *session);

uint32_t pkcs11_object2handle(struct pkcs11_object *obj,
			      struct pkcs11_session *session);

struct pkcs11_object *create_token_object(struct obj_attrs *head,
					  TEE_UUID *uuid,
					  struct ck_token *token);

enum pkcs11_rc create_object(void *session, struct obj_attrs *attributes,
			     uint32_t *handle);

void cleanup_persistent_object(struct pkcs11_object *obj,
			       struct ck_token *token);

void destroy_object(struct pkcs11_session *session,
		    struct pkcs11_object *object, bool session_object_only);

/*
 * 从 PKCS11 命令解析器调用的入口函数
 * 
 * 这些函数实现了 PKCS#11 对象管理的各个命令：
 * - 创建和销毁对象
 * - 查找对象（初始化、查找、结束）
 * - 获取和设置对象属性
 * - 复制对象
 * - 获取对象大小
 */
enum pkcs11_rc entry_create_object(struct pkcs11_client *client,
				   uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_destroy_object(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_find_objects_init(struct pkcs11_client *client,
				       uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_find_objects(struct pkcs11_client *client,
				  uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_find_objects_final(struct pkcs11_client *client,
					uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_get_attribute_value(struct pkcs11_client *client,
					 uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_get_object_size(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_set_attribute_value(struct pkcs11_client *client,
					 uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_copy_object(struct pkcs11_client *client, uint32_t ptypes,
				 TEE_Param *params);

void release_session_find_obj_context(struct pkcs11_session *session);

#endif /*PKCS11_TA_OBJECT_H*/
