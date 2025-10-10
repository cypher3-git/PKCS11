// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

/*
 * ==================================================================================
 * 模块名称: PKCS#11对象管理 (Object Management)
 * 文件功能: 实现PKCS#11对象的创建、查询、修改、复制和销毁操作
 * ==================================================================================
 * 
 * 【模块职责】
 * 1. 对象生命周期：创建、销毁、复制对象
 * 2. 对象存储：会话对象（内存）和令牌对象（持久化）
 * 3. 对象查找：基于属性模板的对象搜索
 * 4. 属性操作：获取、设置对象属性
 * 5. 句柄管理：对象句柄的分配和查找
 * 6. 对象分类：密钥对象、数据对象、证书对象
 * 
 * 【对象类型】
 * - CKO_DATA:       数据对象（用户数据）
 * - CKO_SECRET_KEY: 对称密钥（AES、HMAC等）
 * - CKO_PUBLIC_KEY: 公钥（RSA、EC公钥）
 * - CKO_PRIVATE_KEY: 私钥（RSA、EC私钥）
 * - CKO_CERTIFICATE: 证书对象
 * 
 * 【存储策略】
 * - 会话对象：存储在会话的object_list中，会话关闭时销毁
 * - 令牌对象：存储在令牌的object_list + 持久化存储，永久保存
 * - 持久化：使用TEE安全存储（通过UUID标识）
 * 
 * 【核心数据结构】
 * struct pkcs11_object {
 *     LIST_ENTRY link;           // 链表节点
 *     struct obj_attrs *attributes; // 属性列表
 *     TEE_ObjectHandle key_handle;  // TEE 密钥句柄
 *     uint32_t key_type;           // TEE 密钥类型
 *     struct ck_token *token;      // 所属令牌
 *     TEE_UUID *uuid;              // 持久化 UUID（仅令牌对象）
 *     TEE_ObjectHandle attribs_hdl; // 持久化属性句柄
 * };
 * 
 * 【对象查找流程】
 * 1. C_FindObjectsInit(): 初始化查找，保存查找模板
 * 2. C_FindObjects():     返回匹配的对象句柄
 * 3. C_FindObjectsFinal(): 结束查找，释放查找上下文
 * 
 * 【命令实现】
 * - entry_create_object():         C_CreateObject
 * - entry_destroy_object():        C_DestroyObject
 * - entry_find_objects_init():     C_FindObjectsInit
 * - entry_find_objects():          C_FindObjects
 * - entry_find_objects_final():    C_FindObjectsFinal
 * - entry_get_attribute_value():   C_GetAttributeValue
 * - entry_set_attribute_value():   C_SetAttributeValue
 * - entry_copy_object():           C_CopyObject
 * - entry_get_object_size():       C_GetObjectSize
 */

#include <assert.h>
#include <inttypes.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "attributes.h"
#include "handle.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "sanitize_object.h"
#include "serializer.h"

/*
 * 临时对象列表
 * 
 * 用于注册已分配的 pkcs11_object 实例，以便 destroy_object() 可以无条件地
 * 从其列表中移除对象，无论是来自对象销毁请求，还是因为对象创建在完成前失败。
 * 对象在创建完成时会被移动到目标列表。
 */
LIST_HEAD(temp_obj_list, pkcs11_object) temporary_object_list =
	LIST_HEAD_INITIALIZER(temp_obj_list);

static struct ck_token *get_session_token(void *session);

struct pkcs11_object *pkcs11_handle2object(uint32_t handle,
					   struct pkcs11_session *session)
{
	struct pkcs11_object *object = NULL;

	object = handle_lookup(get_object_handle_db(session), handle);
	if (!object)
		return NULL;

	/*
	 * 如果对象仅属于会话，则不需要额外检查，
	 * 因为会话对象具有扁平的访问控制空间
	 */
	if (!object->token)
		return object;

	/*
	 * 仅当会话关联到该令牌时才允许访问令牌对象
	 */
	if (object->token != get_session_token(session))
		return NULL;

	return object;
}

uint32_t pkcs11_object2handle(struct pkcs11_object *obj,
			      struct pkcs11_session *session)
{
	return handle_lookup_handle(get_object_handle_db(session), obj);
}

/* 当前处理的 pkcs11 会话与令牌 */

static struct object_list *get_session_objects(void *session)
{
	/* 目前仅支持 pkcs11 会话 */
	struct pkcs11_session *ck_session = session;

	return pkcs11_get_session_objects(ck_session);
}

static struct ck_token *get_session_token(void *session)
{
	struct pkcs11_session *ck_session = session;

	return pkcs11_session2token(ck_session);
}

/* 释放非持久对象的资源 */
static void cleanup_volatile_obj_ref(struct pkcs11_object *obj)
{
	if (!obj)
		return;

	LIST_REMOVE(obj, link);

	if (obj->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj->key_handle);

	if (obj->attribs_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(obj->attribs_hdl);

	TEE_Free(obj->attributes);
	TEE_Free(obj->uuid);
	TEE_Free(obj);
}

/* 释放持久对象的资源（包括易失性资源） */
void cleanup_persistent_object(struct pkcs11_object *obj,
			       struct ck_token *token)
{
	TEE_Result res = TEE_SUCCESS;

	if (!obj)
		return;

	/* 以写属性打开句柄以销毁对象 */
	if (obj->attribs_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(obj->attribs_hdl);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       obj->uuid, sizeof(TEE_UUID),
				       TEE_DATA_FLAG_ACCESS_WRITE_META,
				       &obj->attribs_hdl);
	if (!res)
		TEE_CloseAndDeletePersistentObject1(obj->attribs_hdl);

	obj->attribs_hdl = TEE_HANDLE_NULL;
	destroy_object_uuid(token, obj);

	cleanup_volatile_obj_ref(obj);
}

/*
 * destroy_object - 销毁 PKCS11 TA 对象
 *
 * @session - 请求对象销毁的会话
 * @obj - PKCS11 TA 对象的引用
 * @session_only - 如果为 true，则仅销毁会话对象
 */
void destroy_object(struct pkcs11_session *session, struct pkcs11_object *obj,
		    bool session_only)
{
#ifdef DEBUG
	trace_attributes("[destroy]", obj->attributes);
	if (obj->uuid)
		MSG_RAW("[destroy] obj uuid %pUl", (void *)obj->uuid);
#endif

	if (session_only) {
		/* 因会话关闭而销毁对象 */
		handle_put(get_object_handle_db(session),
			   pkcs11_object2handle(obj, session));
		cleanup_volatile_obj_ref(obj);

		return;
	}

	/* 销毁目标对象（持久或非持久） */
	if (get_bool(obj->attributes, PKCS11_CKA_TOKEN)) {
		assert(obj->uuid);
		/* 尝试两次，否则触发 panic！ */
		if (unregister_persistent_object(session->token, obj->uuid) &&
		    unregister_persistent_object(session->token, obj->uuid))
			TEE_Panic(0);

		handle_put(get_object_handle_db(session),
			   pkcs11_object2handle(obj, session));
		cleanup_persistent_object(obj, session->token);

		token_invalidate_object_handles(obj);
	} else {
		handle_put(get_object_handle_db(session),
			   pkcs11_object2handle(obj, session));
		cleanup_volatile_obj_ref(obj);
	}
}

static struct pkcs11_object *create_obj_instance(struct obj_attrs *head,
						 struct ck_token *token)
{
	struct pkcs11_object *obj = NULL;

	obj = TEE_Malloc(sizeof(struct pkcs11_object), TEE_MALLOC_FILL_ZERO);
	if (!obj)
		return NULL;

	obj->key_handle = TEE_HANDLE_NULL;
	obj->attribs_hdl = TEE_HANDLE_NULL;
	obj->attributes = head;
	obj->token = token;

	return obj;
}

struct pkcs11_object *create_token_object(struct obj_attrs *head,
					  TEE_UUID *uuid,
					  struct ck_token *token)
{
	struct pkcs11_object *obj = create_obj_instance(head, token);

	if (obj)
		obj->uuid = uuid;

	return obj;
}

/*
 * create_object - 从属性和值创建 PKCS11 TA 对象
 *
 * @sess - 请求创建对象的会话
 * @head - 序列化属性的引用
 * @out_handle - 为创建的对象生成的句柄
 */
enum pkcs11_rc create_object(void *sess, struct obj_attrs *head,
			     uint32_t *out_handle)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct pkcs11_object *obj = NULL;
	struct pkcs11_session *session = (struct pkcs11_session *)sess;
	uint32_t obj_handle = 0;

#ifdef DEBUG
	trace_attributes("[create]", head);
#endif

	/*
	 * 我们不检查密钥属性。此时，密钥属性应该是一致且可靠的。
	 */

	obj = create_obj_instance(head, NULL);
	if (!obj)
		return PKCS11_CKR_DEVICE_MEMORY;

	LIST_INSERT_HEAD(&temporary_object_list, obj, link);

	/* 在会话数据库中为对象创建句柄 */
	obj_handle = handle_get(get_object_handle_db(session), obj);
	if (!obj_handle) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto err;
	}

	if (get_bool(obj->attributes, PKCS11_CKA_TOKEN)) {
		TEE_Result res = TEE_SUCCESS;

		/*
		 * 为持久对象获取 ID
		 * 创建文件
		 * 在持久数据库中注册对象
		 * （是否将完整序列移至 persisent_db.c？）
		 */
		size_t size = sizeof(struct obj_attrs) +
			      obj->attributes->attrs_size;
		uint32_t tee_obj_flags = TEE_DATA_FLAG_ACCESS_READ |
					 TEE_DATA_FLAG_ACCESS_WRITE |
					 TEE_DATA_FLAG_ACCESS_WRITE_META;

		rc = create_object_uuid(get_session_token(session), obj);
		if (rc)
			goto err;

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 obj->uuid, sizeof(TEE_UUID),
						 tee_obj_flags,
						 TEE_HANDLE_NULL,
						 obj->attributes, size,
						 &obj->attribs_hdl);
		if (res) {
			rc = tee2pkcs_error(res);
			goto err;
		}

		rc = register_persistent_object(get_session_token(session),
						obj->uuid);
		if (rc)
			goto err;

		TEE_CloseObject(obj->attribs_hdl);
		obj->attribs_hdl = TEE_HANDLE_NULL;

		/* 将对象从临时列表移至目标令牌列表 */
		LIST_REMOVE(obj, link);
		LIST_INSERT_HEAD(&session->token->object_list, obj, link);
	} else {
		/* 将对象从临时列表移至目标会话列表 */
		LIST_REMOVE(obj, link);
		LIST_INSERT_HEAD(get_session_objects(session), obj, link);
	}

	*out_handle = obj_handle;

	return PKCS11_CKR_OK;
err:
	/* 确保提供的 "head" 不会被释放 */
	obj->attributes = NULL;
	handle_put(get_object_handle_db(session), obj_handle);
	if (get_bool(head, PKCS11_CKA_TOKEN))
		cleanup_persistent_object(obj, session->token);
	else
		cleanup_volatile_obj_ref(obj);

	return rc;
}

enum pkcs11_rc entry_create_object(struct pkcs11_client *client,
				   uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct obj_attrs *head = NULL;
	struct pkcs11_object_head *template = NULL;
	size_t template_size = 0;
	uint32_t obj_handle = 0;

	/*
	 * 收集请求的参数
	 */

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(obj_handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	template_size = sizeof(*template) + template->attrs_size;

	/*
	 * 为请求的对象属性准备干净的初始状态。
	 * 完成后释放临时模板。
	 */
	rc = create_attributes_from_template(&head, template, template_size,
					     NULL, PKCS11_FUNCTION_IMPORT,
					     PKCS11_PROCESSING_IMPORT,
					     PKCS11_CKO_UNDEFINED_ID);
	TEE_Free(template);
	template = NULL;
	if (rc)
		goto out;

	/* 设置密钥检查值属性 */
	rc = set_check_value_attr(&head);
	if (rc)
		goto out;

	/*
	 * 检查目标对象属性是否匹配目标处理
	 * 检查目标对象属性是否匹配令牌状态
	 */
	rc = check_created_attrs_against_processing(PKCS11_PROCESSING_IMPORT,
						    head);
	if (rc)
		goto out;

	rc = check_created_attrs_against_token(session, head);
	if (rc)
		goto out;

	rc = check_access_attrs_against_token(session, head);
	if (rc)
		goto out;

	/*
	 * 此阶段对象几乎已创建：所有属性都在 @head 中引用，
	 * 包括密钥值，并假定是可靠的。现在需要注册它并为其获取句柄。
	 */
	rc = create_object(session, head, &obj_handle);
	if (rc)
		goto out;

	/*
	 * 现在 obj_handle（通过相关的 struct pkcs11_object 实例）
	 * 拥有保存对象属性的序列化缓冲区。我们将 head 中的引用清零为 NULL，
	 * 因为序列化器对象现在从 obj_handle 引用。这允许函数退出时顺利释放。
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(obj_handle));
	out->memref.size = sizeof(obj_handle);

	DMSG("PKCS11 session %"PRIu32": import object %#"PRIx32,
	     session->handle, obj_handle);

out:
	TEE_Free(template);
	TEE_Free(head);

	return rc;
}

enum pkcs11_rc entry_destroy_object(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	TEE_Param *ctrl = params;
	struct serialargs ctrlargs = { };
	uint32_t object_handle = 0;
	struct pkcs11_session *session = NULL;
	struct pkcs11_object *object = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&ctrlargs, &object_handle);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	object = pkcs11_handle2object(object_handle, session);
	if (!object)
		return PKCS11_CKR_OBJECT_HANDLE_INVALID;

	/* 在只读会话期间只能销毁会话对象 */
	if (get_bool(object->attributes, PKCS11_CKA_TOKEN) &&
	    !pkcs11_session_is_read_write(session)) {
		DMSG("Can't destroy persistent object");
		return PKCS11_CKR_SESSION_READ_ONLY;
	}

	/*
	 * 除非普通用户已登录，否则只能销毁公共对象
	 */
	rc = check_access_attrs_against_token(session, object->attributes);
	if (rc)
		return PKCS11_CKR_USER_NOT_LOGGED_IN;

	/* PKCS11_CKA_DESTROYABLE 为 false 的对象不可销毁 */
	if (!get_bool(object->attributes, PKCS11_CKA_DESTROYABLE))
		return PKCS11_CKR_ACTION_PROHIBITED;

	destroy_object(session, object, false);

	DMSG("PKCS11 session %"PRIu32": destroy object %#"PRIx32,
	     session->handle, object_handle);

	return rc;
}

static void release_find_obj_context(struct pkcs11_find_objects *find_ctx)
{
	if (!find_ctx)
		return;

	TEE_Free(find_ctx->attributes);
	TEE_Free(find_ctx->handles);
	TEE_Free(find_ctx);
}

static enum pkcs11_rc find_ctx_add(struct pkcs11_find_objects *find_ctx,
				   uint32_t handle)
{
	uint32_t *hdls = TEE_Realloc(find_ctx->handles,
				     (find_ctx->count + 1) * sizeof(*hdls));

	if (!hdls)
		return PKCS11_CKR_DEVICE_MEMORY;

	find_ctx->handles = hdls;

	*(find_ctx->handles + find_ctx->count) = handle;
	find_ctx->count++;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_find_objects_init(struct pkcs11_client *client,
				       uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_session *sess = NULL;
	struct pkcs11_object_head *template = NULL;
	struct obj_attrs *req_attrs = NULL;
	struct pkcs11_object *obj = NULL;
	struct pkcs11_find_objects *find_ctx = NULL;
	struct handle_db *object_db = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

/* 仅在没有正在进行的操作时搜索对象 */
	if (session_is_active(session)) {
		rc = PKCS11_CKR_OPERATION_ACTIVE;
		goto out;
	}

	if (session->find_ctx) {
		EMSG("Active object search already in progress");
		rc = PKCS11_CKR_FUNCTION_FAILED;
		goto out;
	}

	rc = sanitize_client_object(&req_attrs, template,
				    sizeof(*template) + template->attrs_size,
				    PKCS11_UNDEFINED_ID, PKCS11_UNDEFINED_ID);
	if (rc)
		goto out;

	/* 必须零初始化结构 */
	find_ctx = TEE_Malloc(sizeof(*find_ctx), TEE_MALLOC_FILL_ZERO);
	if (!find_ctx) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto out;
	}

	TEE_Free(template);
	template = NULL;

	switch (get_class(req_attrs)) {
	case PKCS11_CKO_UNDEFINED_ID:
	/* 未指定类别时在数据对象中搜索 */
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_DATA:
	case PKCS11_CKO_CERTIFICATE:
		break;
	default:
		EMSG("Find object of class %s (%"PRIu32") is not supported",
		     id2str_class(get_class(req_attrs)),
		     get_class(req_attrs));
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	/*
	 * 扫描所有对象（会话对象和持久对象），并设置与调用者属性匹配的候选列表。
	 */

	/* 首先扫描所有会话对象 */
	TAILQ_FOREACH(sess, get_session_list(session), link) {
		LIST_FOREACH(obj, &sess->object_list, link) {
			/*
			 * 跳过所有令牌对象，因为它们可能来自会话无权访问的
			 * 不同令牌
			 */
			if (obj->token)
				continue;

			if (!attributes_match_reference(obj->attributes,
							req_attrs))
				continue;

			rc = find_ctx_add(find_ctx,
					  pkcs11_object2handle(obj, session));
			if (rc)
				goto out;
		}
	}

	object_db = get_object_handle_db(session);

	/* 扫描令牌对象 */
	LIST_FOREACH(obj, &session->token->object_list, link) {
		uint32_t handle = 0;
		bool new_load = false;

		if (!obj->attributes) {
			rc = load_persistent_object_attributes(obj);
			if (rc) {
				rc = PKCS11_CKR_GENERAL_ERROR;
				goto out;
			}

			new_load = true;
		}

		if (!obj->attributes ||
		    check_access_attrs_against_token(session,
						     obj->attributes) ||
		    !attributes_match_reference(obj->attributes, req_attrs)) {
			if (new_load)
				release_persistent_object_attributes(obj);

			continue;
		}

		/* 解析对象句柄 */
		handle = pkcs11_object2handle(obj, session);
		if (!handle) {
			handle = handle_get(object_db, obj);
			if (!handle) {
				rc = PKCS11_CKR_DEVICE_MEMORY;
				goto out;
			}
		}

		rc = find_ctx_add(find_ctx, handle);
		if (rc)
			goto out;
	}

	find_ctx->attributes = req_attrs;
	req_attrs = NULL;
	session->find_ctx = find_ctx;
	find_ctx = NULL;
	rc = PKCS11_CKR_OK;

out:
	TEE_Free(req_attrs);
	TEE_Free(template);
	release_find_obj_context(find_ctx);

	return rc;
}

enum pkcs11_rc entry_find_objects(struct pkcs11_client *client,
				  uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_find_objects *ctx = NULL;
	uint8_t *out_handles = NULL;
	size_t out_count = 0;
	size_t count = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	out_count = out->memref.size / sizeof(uint32_t);
	out_handles = out->memref.buffer;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	ctx = session->find_ctx;

	if (!ctx)
		return PKCS11_CKR_OPERATION_NOT_INITIALIZED;

	for (count = 0; ctx->next < ctx->count && count < out_count;
	     ctx->next++, count++)
		TEE_MemMove(out_handles + count * sizeof(uint32_t),
			    ctx->handles + ctx->next, sizeof(uint32_t));

	/* 根据提供的句柄数量更新输出缓冲区 */
	out->memref.size = count * sizeof(uint32_t);

	DMSG("PKCS11 session %"PRIu32": finding objects", session->handle);

	return PKCS11_CKR_OK;
}

void release_session_find_obj_context(struct pkcs11_session *session)
{
	release_find_obj_context(session->find_ctx);
	session->find_ctx = NULL;
}

enum pkcs11_rc entry_find_objects_final(struct pkcs11_client *client,
					uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (!session->find_ctx)
		return PKCS11_CKR_OPERATION_NOT_INITIALIZED;

	release_session_find_obj_context(session);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_get_attribute_value(struct pkcs11_client *client,
					 uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_object_head *template = NULL;
	struct pkcs11_object *obj = NULL;
	uint32_t object_handle = 0;
	char *cur = NULL;
	size_t len = 0;
	char *end = NULL;
	bool attr_sensitive = 0;
	bool attr_type_invalid = 0;
	bool buffer_too_small = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	obj = pkcs11_handle2object(object_handle, session);
	if (!obj) {
		rc = PKCS11_CKR_OBJECT_HANDLE_INVALID;
		goto out;
	}

	rc = check_access_attrs_against_token(session, obj->attributes);
	if (rc) {
		rc = PKCS11_CKR_OBJECT_HANDLE_INVALID;
		goto out;
	}

	/* 遍历属性并设置其值 */
	/*
	 * 1. 如果对象的指定属性（即由 type 字段指定的属性）因对象
	 * 敏感或不可提取而无法显示，则该三元组中的 ulValueLen 字段
	 * 被修改为保存值 PKCS11_CK_UNAVAILABLE_INFORMATION。
	 *
	 * 2. 否则，如果对象的指定值无效（对象不具有此类属性），则该
	 * 三元组中的 ulValueLen 字段被修改为保存值
	 * PKCS11_CK_UNAVAILABLE_INFORMATION。
	 *
	 * 3. 否则，如果 pValue 字段的值为 NULL_PTR，则 ulValueLen 字段
	 * 被修改为保存对象指定属性的确切长度。
	 *
	 * 4. 否则，如果 ulValueLen 中指定的长度足以容纳对象指定属性的值，
	 * 则该属性被复制到 pValue 所指向的缓冲区中，并且 ulValueLen 字段
	 * 被修改为保存属性的确切长度。
	 *
	 * 5. 否则，ulValueLen 字段被修改为保存值
	 * PKCS11_CK_UNAVAILABLE_INFORMATION。
	 */
	cur = (char *)template + sizeof(struct pkcs11_object_head);
	end = cur + template->attrs_size;

	for (; cur < end; cur += len) {
		struct pkcs11_attribute_head *cli_ref = (void *)cur;
		struct pkcs11_attribute_head cli_head = { };
		void *data_ptr = NULL;

		/* 复制头部以确保正确对齐 */
		TEE_MemMove(&cli_head, cli_ref, sizeof(cli_head));

		len = sizeof(*cli_ref) + cli_head.size;

		/* 将隐藏属性视为缺失属性 */
		if (attribute_is_hidden(&cli_head)) {
			cli_head.size = PKCS11_CK_UNAVAILABLE_INFORMATION;
			TEE_MemMove(&cli_ref->size, &cli_head.size,
				    sizeof(cli_head.size));
			attr_type_invalid = 1;
			continue;
		}

		/* 我们不支持获取间接模板的值 */
		if (pkcs11_attr_has_indirect_attributes(cli_head.id)) {
			attr_type_invalid = 1;
			continue;
		}

		/* 检查 1. */
		if (!attribute_is_exportable(&cli_head, obj)) {
			cli_head.size = PKCS11_CK_UNAVAILABLE_INFORMATION;
			TEE_MemMove(&cli_ref->size, &cli_head.size,
				    sizeof(cli_head.size));
			attr_sensitive = 1;
			continue;
		}

		/* 从模板数据获取实际数据指针 */
		data_ptr = cli_head.size ? cli_ref->data : NULL;

		/*
		 * 我们假设如果 size 为 0，则 pValue 为 NULL，
		 * 因此我们返回所需缓冲区的大小（3., 4.）
		 */
		rc = get_attribute(obj->attributes, cli_head.id, data_ptr,
				   &cli_head.size);
		/* 检查 2. */
		switch (rc) {
		case PKCS11_CKR_OK:
			break;
		case PKCS11_RV_NOT_FOUND:
			cli_head.size = PKCS11_CK_UNAVAILABLE_INFORMATION;
			attr_type_invalid = 1;
			break;
		case PKCS11_CKR_BUFFER_TOO_SMALL:
			if (data_ptr)
				buffer_too_small = 1;
			break;
		default:
			rc = PKCS11_CKR_GENERAL_ERROR;
			goto out;
		}

		TEE_MemMove(&cli_ref->size, &cli_head.size,
			    sizeof(cli_head.size));
	}

	/*
	 * 如果情况 1 适用于任何请求的属性，则调用应返回值
	 * CKR_ATTRIBUTE_SENSITIVE。如果情况 2 适用于任何请求的属性，
	 * 则调用应返回值 CKR_ATTRIBUTE_TYPE_INVALID。如果情况 5 适用于
	 * 任何请求的属性，则调用应返回值 CKR_BUFFER_TOO_SMALL。
	 * 如常，如果这些错误代码中的多个适用，Cryptoki 可以返回其中任何一个。
	 * 仅当没有一个适用于任何请求的属性时，才会返回 CKR_OK。
	 */

	rc = PKCS11_CKR_OK;
	if (attr_sensitive)
		rc = PKCS11_CKR_ATTRIBUTE_SENSITIVE;
	if (attr_type_invalid)
		rc = PKCS11_CKR_ATTRIBUTE_TYPE_INVALID;
	if (buffer_too_small)
		rc = PKCS11_CKR_BUFFER_TOO_SMALL;

	/* 将更新的模板移动到输出缓冲区 */
	TEE_MemMove(out->memref.buffer, template, out->memref.size);

	DMSG("PKCS11 session %"PRIu32": get attributes %#"PRIx32,
	     session->handle, object_handle);

out:
	TEE_Free(template);

	return rc;
}

enum pkcs11_rc entry_get_object_size(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	uint32_t object_handle = 0;
	struct pkcs11_object *obj = NULL;
	uint32_t obj_size = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	obj = pkcs11_handle2object(object_handle, session);
	if (!obj)
		return PKCS11_CKR_OBJECT_HANDLE_INVALID;

	rc = check_access_attrs_against_token(session, obj->attributes);
	if (rc)
		return PKCS11_CKR_OBJECT_HANDLE_INVALID;

	if (out->memref.size != sizeof(uint32_t))
		return PKCS11_CKR_ARGUMENTS_BAD;

	obj_size = ((struct obj_attrs *)obj->attributes)->attrs_size +
		   sizeof(struct obj_attrs);
	TEE_MemMove(out->memref.buffer, &obj_size, sizeof(obj_size));

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_set_attribute_value(struct pkcs11_client *client,
					 uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_object_head *template = NULL;
	size_t template_size = 0;
	struct pkcs11_object *obj = NULL;
	struct obj_attrs *head = NULL;
	struct obj_attrs *head_new = NULL;
	struct obj_attrs *head_old = NULL;
	uint32_t object_handle = 0;
	enum processing_func function = PKCS11_FUNCTION_MODIFY;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	obj = pkcs11_handle2object(object_handle, session);
	if (!obj) {
		rc = PKCS11_CKR_OBJECT_HANDLE_INVALID;
		goto out;
	}

	/* 在只读会话期间只能修改会话对象 */
	if (object_is_token(obj->attributes) &&
	    !pkcs11_session_is_read_write(session)) {
		DMSG("Can't modify persistent object in a RO session");
		rc = PKCS11_CKR_SESSION_READ_ONLY;
		goto out;
	}

	/*
	 * 仅当普通用户已登录时，才允许修改非公共对象
	 */
	rc = check_access_attrs_against_token(session, obj->attributes);
	if (rc) {
		rc = PKCS11_CKR_USER_NOT_LOGGED_IN;
		goto out;
	}

	/* PKCS11_CKA_MODIFIABLE 为 false 的对象不可修改 */
	if (!object_is_modifiable(obj->attributes)) {
		rc = PKCS11_CKR_ACTION_PROHIBITED;
		goto out;
	}

	template_size = sizeof(*template) + template->attrs_size;

	/*
	 * Prepare a clean initial state (@head) for the template. Helps in
	 * removing any duplicates or inconsistent values from the
	 * template.
	 */
	rc = create_attributes_from_template(&head, template, template_size,
					     NULL, function,
					     PKCS11_CKM_UNDEFINED_ID,
					     PKCS11_CKO_UNDEFINED_ID);
	if (rc)
		goto out;

	/* 检查 @head 中的属性是否可修改 */
	rc = check_attrs_against_modification(session, head, obj, function);
	if (rc)
		goto out;

	/* 创建要修改的新对象属性 */
	template_size = sizeof(*obj->attributes) + obj->attributes->attrs_size;
	head_new = TEE_Malloc(template_size, TEE_MALLOC_FILL_ZERO);
	if (!head_new) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto out;
	}

	TEE_MemMove(head_new, obj->attributes, template_size);

	/*
	 * 所有检查完成。@head 中的属性已经过检查，
	 * 现在可用于设置/修改对象属性。
	 */
	rc = modify_attributes_list(&head_new, head);
	if (rc)
		goto out;

	/* 设置密钥检查值属性 */
	rc = set_check_value_attr(&head_new);
	if (rc)
		goto out;

	/* 更新对象 */
	head_old = obj->attributes;
	obj->attributes = head_new;
	head_new = NULL;

	if (get_bool(obj->attributes, PKCS11_CKA_TOKEN)) {
		rc = update_persistent_object_attributes(obj);
		if (rc) {
			TEE_Free(obj->attributes);
			obj->attributes = head_old;
			goto out;
		}
	}

	TEE_Free(head_old);

	DMSG("PKCS11 session %"PRIu32": set attributes %#"PRIx32,
	     session->handle, object_handle);

out:
	TEE_Free(head);
	TEE_Free(head_new);
	TEE_Free(template);
	return rc;
}

enum pkcs11_rc entry_copy_object(struct pkcs11_client *client, uint32_t ptypes,
				 TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_object_head *template = NULL;
	struct obj_attrs *head = NULL;
	struct obj_attrs *head_new = NULL;
	size_t template_size = 0;
	struct pkcs11_object *obj = NULL;
	uint32_t object_handle = 0;
	uint32_t obj_handle = 0;
	enum processing_func function = PKCS11_FUNCTION_COPY;
	enum pkcs11_class_id class = PKCS11_CKO_UNDEFINED_ID;

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(obj_handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	obj = pkcs11_handle2object(object_handle, session);
	if (!obj) {
		rc = PKCS11_CKR_OBJECT_HANDLE_INVALID;
		goto out;
	}

	/* 在只读会话期间只能修改会话对象 */
	if (object_is_token(obj->attributes) &&
	    !pkcs11_session_is_read_write(session)) {
		DMSG("Can't modify persistent object in a RO session");
		rc = PKCS11_CKR_SESSION_READ_ONLY;
		goto out;
	}

	/*
	 * 仅当普通用户已登录时，才允许修改非公共对象
	 */
	rc = check_access_attrs_against_token(session, obj->attributes);
	if (rc) {
		rc = PKCS11_CKR_USER_NOT_LOGGED_IN;
		goto out;
	}

	/* PKCS11_CKA_COPYABLE 为 false 的对象不能被复制 */
	if (!object_is_copyable(obj->attributes)) {
		rc = PKCS11_CKR_ACTION_PROHIBITED;
		goto out;
	}

	template_size = sizeof(*template) + template->attrs_size;

	/*
	 * Prepare a clean initial state (@head) for the template. Helps in
	 * removing any duplicates or inconsistent values from the
	 * template.
	 */
	rc = create_attributes_from_template(&head, template, template_size,
					     NULL, function,
					     PKCS11_CKM_UNDEFINED_ID,
					     PKCS11_CKO_UNDEFINED_ID);
	if (rc)
		goto out;

	/* 检查 @head 中的属性是否可修改 */
	rc = check_attrs_against_modification(session, head, obj, function);
	if (rc)
		goto out;

	class = get_class(obj->attributes);

	if (class == PKCS11_CKO_SECRET_KEY ||
	    class == PKCS11_CKO_PRIVATE_KEY) {
		/*
		 * 如果传递模板（@head）中的 CKA_EXTRACTABLE 属性被修改为
		 * CKA_FALSE，则复制对象中的 CKA_NEVER_EXTRACTABLE 也应
		 * 更改为 CKA_FALSE。因此，将其添加到传递的模板中。
		 */
		uint8_t bbool = 0;
		uint32_t size = sizeof(bbool);

		rc = get_attribute(head, PKCS11_CKA_EXTRACTABLE, &bbool, &size);
		if (!rc && !bbool) {
			rc = add_attribute(&head, PKCS11_CKA_NEVER_EXTRACTABLE,
					   &bbool, sizeof(uint8_t));
			if (rc)
				goto out;
		}
		rc = PKCS11_CKR_OK;
	}

	/*
	 * 所有检查都通过了。为新对象在 @head_new 中创建包含对象属性的
	 * 序列化缓冲区的副本
	 */
	template_size = sizeof(*obj->attributes) + obj->attributes->attrs_size;
	head_new = TEE_Malloc(template_size, TEE_MALLOC_FILL_ZERO);
	if (!head_new) {
		rc = PKCS11_CKR_DEVICE_MEMORY;
		goto out;
	}

	TEE_MemMove(head_new, obj->attributes, template_size);

	/*
	 * 根据调用者给定的模板 @head 修改复制的属性 @head_new
	 */
	rc = modify_attributes_list(&head_new, head);
	if (rc)
		goto out;

	/* 设置密钥检查值属性 */
	rc = set_check_value_attr(&head_new);
	if (rc)
		goto out;

	/*
	 * At this stage the object is almost created: all its attributes are
	 * referenced in @head_new, including the key value and are assumed
	 * reliable. Now need to register it and get a handle for it.
	 */
	rc = create_object(session, head_new, &obj_handle);
	if (rc)
		goto out;

	/*
	 * Now obj_handle (through the related struct pkcs11_object
	 * instance) owns the serialized buffer that holds the object
	 * attributes. We clear reference in head to NULL as the serializer
	 * object is now referred from obj_handle. This allows smooth pass
	 * through free at function exit.
	 */
	head_new = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(obj_handle));
	out->memref.size = sizeof(obj_handle);

	DMSG("PKCS11 session %"PRIu32": copy object %#"PRIx32,
	     session->handle, obj_handle);

out:
	TEE_Free(head_new);
	TEE_Free(head);
	TEE_Free(template);
	return rc;
}
