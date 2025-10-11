// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

/*
 * ==================================================================================
 * 模块名称: TA入口与命令路由 (TA Entry Point & Command Dispatcher)
 * 文件功能: PKCS#11 TA的生命周期管理和命令分发中心
 * ==================================================================================
 * 
 * 【模块职责】
 * 1. TA生命周期：创建、销毁TA实例
 * 2. 会话管理：打开、关闭客户端会话
 * 3. 命令路由：将52种PKCS#11命令分发到对应处理模块
 * 4. 参数验证：检查命令参数的合法性
 * 5. 返回码管理：统一处理返回值
 * 
 * 【GPD TEE标准接口实现】
 * - TA_CreateEntryPoint(): TA加载时调用（初始化令牌）
 * - TA_DestroyEntryPoint(): TA卸载时调用（清理资源）
 * - TA_OpenSessionEntryPoint(): 客户端连接时调用（注册客户端）
 * - TA_CloseSessionEntryPoint(): 客户端断开时调用（注销客户端）
 * - TA_InvokeCommandEntryPoint(): 处理客户端命令请求（核心分发函数）
 * 
 * 【命令分类】
 * 1. 令牌管理(5个)：SLOT_LIST, SLOT_INFO, TOKEN_INFO, MECHANISM_IDS, MECHANISM_INFO
 * 2. 会话管理(4个)：OPEN_SESSION, CLOSE_SESSION, CLOSE_ALL_SESSIONS, SESSION_INFO
 * 3. 用户认证(5个)：INIT_TOKEN, INIT_PIN, SET_PIN, LOGIN, LOGOUT
 * 4. 对象管理(7个)：CREATE, DESTROY, FIND_INIT/FIND/FIND_FINAL, GET_ATTR, SET_ATTR, COPY, SIZE
 * 5. 加解密(10个)：ENCRYPT/DECRYPT的INIT/UPDATE/FINAL/ONESHOT
 * 6. 签名验签(10个)：SIGN/VERIFY的INIT/UPDATE/FINAL/ONESHOT
 * 7. 摘要(5个)：DIGEST_INIT/UPDATE/KEY/FINAL/ONESHOT
 * 8. 密钥生成(2个)：GENERATE_KEY, GENERATE_KEY_PAIR
 * 9. 密钥派生(1个)：DERIVE_KEY
 * 10. 密钥包装(2个)：WRAP_KEY, UNWRAP_KEY
 * 11. 随机数(2个)：SEED_RANDOM, GENERATE_RANDOM
 * 
 * 【参数约定】
 * Param#0: 控制参数（输入+输出）
 *   - 输入: 序列化的命令参数
 *   - 输出: 32位PKCS#11返回码
 * Param#1: 输入数据（可选）
 * Param#2: 输出数据或句柄（可选）
 * Param#3: 保留（未使用）
 * 
 * 【错误处理】
 * - PKCS11错误码: 写入Param#0返回
 * - TEE错误码: 直接return
 * - 特殊处理: BUFFER_TOO_SMALL -> TEE_ERROR_SHORT_BUFFER
 */

#include <assert.h>
#include <compiler.h>
#include <pkcs11_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "object.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"

/*
 * TA创建入口点（TA加载时调用一次）
 * 
 * 功能：
 * - 初始化所有PKCS#11令牌（从持久化存储加载）
 * - 创建令牌数据结构
 * 
 * 返回值：
 * - TEE_SUCCESS: 初始化成功
 * - 其他: 初始化失败，TA加载失败
 */
TEE_Result TA_CreateEntryPoint(void)
{
	return pkcs11_init();
}

/*
 * TA销毁入口点（TA卸载时调用一次）
 * 
 * 功能：
 * - 清理所有资源
 * - 保存持久化数据
 * - 释放令牌结构
 */
void TA_DestroyEntryPoint(void)
{
	pkcs11_deinit();
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void **tee_session)
{
	struct pkcs11_client *client = register_client();

	if (!client)
		return TEE_ERROR_OUT_OF_MEMORY;

	*tee_session = client;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *tee_session)
{
	struct pkcs11_client *client = tee_session2client(tee_session);

	unregister_client(client);
}

/*
 * 调用命令 PKCS11_CMD_PING 的入口点
 *
 * 返回一个 PKCS11_CKR_* 错误码，同时写入输出参数 #0
 */
/*
 * entry_ping - PKCS#11 TA 的 Ping 功能
 * 
 * 功能：用于测试 TA 是否正常运行，并返回 TA 的版本信息
 * 
 * @ptypes: 参数类型掩码，用于验证传入参数的类型
 * @params: TEE 参数数组
 *          params[0] - INOUT 类型的内存引用（用于握手验证）
 *          params[2] - OUTPUT 类型的内存引用（用于返回版本号）
 * 
 * 返回值：
 *   PKCS11_CKR_OK - 成功
 *   PKCS11_CKR_ARGUMENTS_BAD - 参数类型或大小不匹配
 */
static enum pkcs11_rc entry_ping(uint32_t ptypes, TEE_Param *params)
{
	/* 期望的参数类型：INOUT, NONE, OUTPUT, NONE */
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *out = params + 2;  /* 指向输出参数（版本信息） */
	
	/* TA 版本号数组：主版本号.次版本号.补丁版本号 */
	const uint32_t ver[] = {
		PKCS11_TA_VERSION_MAJOR,
		PKCS11_TA_VERSION_MINOR,
		PKCS11_TA_VERSION_PATCH,
	};

	/* 验证参数类型和大小是否符合预期 */
	if (ptypes != exp_pt ||
	    params[0].memref.size != TEE_PARAM0_SIZE_MIN ||
	    out->memref.size != sizeof(ver))
		return PKCS11_CKR_ARGUMENTS_BAD;

	/* 将版本信息复制到输出缓冲区 */
	TEE_MemMove(out->memref.buffer, ver, sizeof(ver));

	return PKCS11_CKR_OK;
}

/*
 * param_is_none - 检查参数是否为 NONE 类型
 * 
 * 功能：判断指定索引位置的参数类型是否为 TEE_PARAM_TYPE_NONE（即未使用的参数）
 * 
 * @ptypes: 参数类型掩码
 * @index: 参数索引（0-3）
 * 
 * 返回值：true - 该参数为 NONE 类型；false - 该参数为其他类型
 */
static bool __maybe_unused param_is_none(uint32_t ptypes, unsigned int index)
{
	return TEE_PARAM_TYPE_GET(ptypes, index) ==
	       TEE_PARAM_TYPE_NONE;
}

/*
 * param_is_memref - 检查参数是否为内存引用类型
 * 
 * 功能：判断指定索引位置的参数是否为内存引用类型（INPUT/OUTPUT/INOUT 之一）
 *       这些类型用于在正常世界（Normal World）和安全世界（Secure World）之间传递数据
 * 
 * @ptypes: 参数类型掩码
 * @index: 参数索引（0-3）
 * 
 * 返回值：true - 该参数为内存引用类型；false - 该参数为其他类型
 */
static bool __maybe_unused param_is_memref(uint32_t ptypes, unsigned int index)
{
	switch (TEE_PARAM_TYPE_GET(ptypes, index)) {
	case TEE_PARAM_TYPE_MEMREF_INPUT:   /* 输入内存引用 */
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:  /* 输出内存引用 */
	case TEE_PARAM_TYPE_MEMREF_INOUT:   /* 输入输出内存引用 */
		return true;
	default:
		return false;
	}
}

/*
 * param_is_input - 检查参数是否为输入内存引用类型
 * 
 * 功能：判断指定索引位置的参数是否为只读输入类型（INPUT）
 *       INPUT 类型表示数据从正常世界传递到安全世界，TA 只能读取
 * 
 * @ptypes: 参数类型掩码
 * @index: 参数索引（0-3）
 * 
 * 返回值：true - 该参数为 INPUT 类型；false - 该参数为其他类型
 */
static bool __maybe_unused param_is_input(uint32_t ptypes, unsigned int index)
{
	return TEE_PARAM_TYPE_GET(ptypes, index) ==
	       TEE_PARAM_TYPE_MEMREF_INPUT;
}

/*
 * param_is_output - 检查参数是否为输出内存引用类型
 * 
 * 功能：判断指定索引位置的参数是否为只写输出类型（OUTPUT）
 *       OUTPUT 类型表示数据从安全世界返回到正常世界，TA 只能写入
 * 
 * @ptypes: 参数类型掩码
 * @index: 参数索引（0-3）
 * 
 * 返回值：true - 该参数为 OUTPUT 类型；false - 该参数为其他类型
 */
static bool __maybe_unused param_is_output(uint32_t ptypes, unsigned int index)
{
	return TEE_PARAM_TYPE_GET(ptypes, index) ==
	       TEE_PARAM_TYPE_MEMREF_OUTPUT;
}

/*
 * TA_InvokeCommandEntryPoint - PKCS11 TA 命令调用入口点
 *
 * 功能：这是 OP-TEE TA 的标准入口函数，处理来自正常世界（Normal World）的所有
 *       PKCS#11 命令请求。函数根据命令 ID 分发到相应的处理函数。
 *
 * @tee_session: TEE 会话指针，包含客户端会话上下文信息
 *               用于标识和管理与客户端的连接状态
 * 
 * @cmd: 命令 ID，指定要执行的 PKCS#11 操作
 *       例如：PKCS11_CMD_PING, PKCS11_CMD_SLOT_LIST, PKCS11_CMD_TOKEN_INFO 等
 * 
 * @ptypes: 参数类型掩码，32 位编码包含 4 个参数的类型信息
 *          每个参数占用 4 位，用于描述参数是 INPUT/OUTPUT/INOUT/NONE 类型
 *          使用 TEE_PARAM_TYPE_GET(ptypes, index) 可获取指定参数的类型
 * 
 * @params: TEE 参数数组，固定 4 个参数（TEE_NUM_PARAMS = 4）
 *          params[0] - 控制参数，必须是 OUTPUT 或 INOUT 类型：
 *                      输入：被调用命令的序列化参数
 *                      输出：细粒度的 PKCS11 返回码（区别于 TEE 返回码）
 *          params[1-3] - 根据具体命令使用，可为 INPUT/OUTPUT/INOUT/NONE 类型
 *
 * 返回值：
 *   TEE_SUCCESS - GPD TEE 层面执行成功（但仍需检查 params[0] 中的 PKCS11 状态码）
 *   TEE_ERROR_SECURITY - 会话验证失败
 *   TEE_ERROR_BAD_PARAMETERS - 参数类型或大小不符合要求
 *
 * 注意：客户端应同时检查 TEE 返回码和 params[0] 中的 PKCS11 状态码
 */
TEE_Result TA_InvokeCommandEntryPoint(void *tee_session, uint32_t cmd,
				      uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	if (!client)
		return TEE_ERROR_SECURITY;

	/* 所有命令处理函数仅检查 4 个参数 */
	COMPILE_TIME_ASSERT(TEE_NUM_PARAMS == 4);

	/*
	 * 参数 #0 必须是输出或输入/输出 memref，
	 * 用于存储被调用命令的输出返回值。
	 */
	switch (TEE_PARAM_TYPE_GET(ptypes, 0)) {
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		if (params[0].memref.size < sizeof(rc))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * 调试日志：输出命令名称和参数信息
	 * 
	 * 输出格式：<命令名> p#0 <大小>@<地址>, p#1 <类型> <大小>@<地址>, p#2 <类型> <大小>@<地址>
	 * 
	 * 示例 1 - PING 命令：
	 *   "PING p#0 4@0x40001000, p#1 in 8@0x40001100, p#2 out 12@0x40001200"
	 *   解释：
	 *     - 命令：PING
	 *     - p#0：4 字节 @ 地址 0x40001000（控制参数，存储返回码）
	 *     - p#1：输入参数，8 字节 @ 地址 0x40001100
	 *     - p#2：输出参数，12 字节 @ 地址 0x40001200
	 * 
	 * 示例 2 - SLOT_LIST 命令：
	 *   "SLOT_LIST p#0 4@0x40002000, p#1 out 256@0x40002100, p#2 --- 0@(nil)"
	 *   解释：
	 *     - 命令：SLOT_LIST（获取插槽列表）
	 *     - p#0：4 字节（返回码）
	 *     - p#1：输出参数，256 字节（用于返回插槽列表）
	 *     - p#2：未使用（显示为 "---"，大小为 0，地址为 NULL）
	 * 
	 * 示例 3 - TOKEN_INFO 命令：
	 *   "TOKEN_INFO p#0 4@0x40003000, p#1 in 4@0x40003100, p#2 out 512@0x40003200"
	 *   解释：
	 *     - 命令：TOKEN_INFO（获取令牌信息）
	 *     - p#0：4 字节（返回码）
	 *     - p#1：输入参数，4 字节（插槽 ID）
	 *     - p#2：输出参数，512 字节（令牌信息结构）
	 */
	DMSG("%s p#0 %zu@%p, p#1 %s %zu@%p, p#2 %s %zu@%p",
	     id2str_ta_cmd(cmd),                    /* 命令名称字符串 */
	     params[0].memref.size, params[0].memref.buffer,  /* p#0 大小和地址 */
	     param_is_input(ptypes, 1) ? "in" :      /* p#1 类型判断 */
	     param_is_output(ptypes, 1) ? "out" : "---",
	     param_is_memref(ptypes, 1) ? params[1].memref.size : 0,    /* p#1 大小 */
	     param_is_memref(ptypes, 1) ? params[1].memref.buffer : NULL,  /* p#1 地址 */
	     param_is_input(ptypes, 2) ? "in" :      /* p#2 类型判断 */
	     param_is_output(ptypes, 2) ? "out" : "---",
	     param_is_memref(ptypes, 2) ? params[2].memref.size : 0,    /* p#2 大小 */
	     param_is_memref(ptypes, 2) ? params[2].memref.buffer : NULL);  /* p#2 地址 */

	switch (cmd) {
	case PKCS11_CMD_PING:
		rc = entry_ping(ptypes, params);
		break;

	case PKCS11_CMD_SLOT_LIST:
		rc = entry_ck_slot_list(ptypes, params);
		break;
	case PKCS11_CMD_SLOT_INFO:
		rc = entry_ck_slot_info(ptypes, params);
		break;
	case PKCS11_CMD_TOKEN_INFO:
		rc = entry_ck_token_info(ptypes, params);
		break;
	case PKCS11_CMD_MECHANISM_IDS:
		rc = entry_ck_token_mecha_ids(ptypes, params);
		break;
	case PKCS11_CMD_MECHANISM_INFO:
		rc = entry_ck_token_mecha_info(ptypes, params);
		break;

	case PKCS11_CMD_OPEN_SESSION:
		rc = entry_ck_open_session(client, ptypes, params);
		break;
	case PKCS11_CMD_CLOSE_SESSION:
		rc = entry_ck_close_session(client, ptypes, params);
		break;
	case PKCS11_CMD_CLOSE_ALL_SESSIONS:
		rc = entry_ck_close_all_sessions(client, ptypes, params);
		break;
	case PKCS11_CMD_SESSION_INFO:
		rc = entry_ck_session_info(client, ptypes, params);
		break;

	case PKCS11_CMD_INIT_TOKEN:
		rc = entry_ck_token_initialize(ptypes, params);
		break;
	case PKCS11_CMD_INIT_PIN:
		rc = entry_ck_init_pin(client, ptypes, params);
		break;
	case PKCS11_CMD_SET_PIN:
		rc = entry_ck_set_pin(client, ptypes, params);
		break;
	case PKCS11_CMD_LOGIN:
		rc = entry_ck_login(client, ptypes, params);
		break;
	case PKCS11_CMD_LOGOUT:
		rc = entry_ck_logout(client, ptypes, params);
		break;

	case PKCS11_CMD_CREATE_OBJECT:
		rc = entry_create_object(client, ptypes, params);
		break;
	case PKCS11_CMD_DESTROY_OBJECT:
		rc = entry_destroy_object(client, ptypes, params);
		break;

	case PKCS11_CMD_ENCRYPT_INIT:
		rc = entry_processing_init(client, ptypes, params,
					   PKCS11_FUNCTION_ENCRYPT);
		break;
	case PKCS11_CMD_DECRYPT_INIT:
		rc = entry_processing_init(client, ptypes, params,
					   PKCS11_FUNCTION_DECRYPT);
		break;
	case PKCS11_CMD_ENCRYPT_UPDATE:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_ENCRYPT,
					   PKCS11_FUNC_STEP_UPDATE);
		break;
	case PKCS11_CMD_DECRYPT_UPDATE:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DECRYPT,
					   PKCS11_FUNC_STEP_UPDATE);
		break;
	case PKCS11_CMD_ENCRYPT_ONESHOT:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_ENCRYPT,
					   PKCS11_FUNC_STEP_ONESHOT);
		break;
	case PKCS11_CMD_DECRYPT_ONESHOT:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DECRYPT,
					   PKCS11_FUNC_STEP_ONESHOT);
		break;
	case PKCS11_CMD_ENCRYPT_FINAL:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_ENCRYPT,
					   PKCS11_FUNC_STEP_FINAL);
		break;
	case PKCS11_CMD_DECRYPT_FINAL:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DECRYPT,
					   PKCS11_FUNC_STEP_FINAL);
		break;
	case PKCS11_CMD_SIGN_INIT:
		rc = entry_processing_init(client, ptypes, params,
					   PKCS11_FUNCTION_SIGN);
		break;
	case PKCS11_CMD_VERIFY_INIT:
		rc = entry_processing_init(client, ptypes, params,
					   PKCS11_FUNCTION_VERIFY);
		break;
	case PKCS11_CMD_SIGN_ONESHOT:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_SIGN,
					   PKCS11_FUNC_STEP_ONESHOT);
		break;
	case PKCS11_CMD_VERIFY_ONESHOT:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_VERIFY,
					   PKCS11_FUNC_STEP_ONESHOT);
		break;
	case PKCS11_CMD_SIGN_UPDATE:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_SIGN,
					   PKCS11_FUNC_STEP_UPDATE);
		break;
	case PKCS11_CMD_VERIFY_UPDATE:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_VERIFY,
					   PKCS11_FUNC_STEP_UPDATE);
		break;
	case PKCS11_CMD_SIGN_FINAL:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_SIGN,
					   PKCS11_FUNC_STEP_FINAL);
		break;
	case PKCS11_CMD_VERIFY_FINAL:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_VERIFY,
					   PKCS11_FUNC_STEP_FINAL);
		break;
	case PKCS11_CMD_GENERATE_KEY:
		rc = entry_generate_secret(client, ptypes, params);
		break;
	case PKCS11_CMD_FIND_OBJECTS_INIT:
		rc = entry_find_objects_init(client, ptypes, params);
		break;
	case PKCS11_CMD_FIND_OBJECTS:
		rc = entry_find_objects(client, ptypes, params);
		break;
	case PKCS11_CMD_FIND_OBJECTS_FINAL:
		rc = entry_find_objects_final(client, ptypes, params);
		break;
	case PKCS11_CMD_GET_ATTRIBUTE_VALUE:
		rc = entry_get_attribute_value(client, ptypes, params);
		break;
	case PKCS11_CMD_GET_OBJECT_SIZE:
		rc = entry_get_object_size(client, ptypes, params);
		break;
	case PKCS11_CMD_SET_ATTRIBUTE_VALUE:
		rc = entry_set_attribute_value(client, ptypes, params);
		break;
	case PKCS11_CMD_COPY_OBJECT:
		rc = entry_copy_object(client, ptypes, params);
		break;
	case PKCS11_CMD_SEED_RANDOM:
		rc = entry_ck_seed_random(client, ptypes, params);
		break;
	case PKCS11_CMD_GENERATE_RANDOM:
		rc = entry_ck_generate_random(client, ptypes, params);
		break;
	case PKCS11_CMD_DERIVE_KEY:
		rc = entry_processing_key(client, ptypes, params,
					  PKCS11_FUNCTION_DERIVE);
		break;
	case PKCS11_CMD_RELEASE_ACTIVE_PROCESSING:
		rc = entry_release_active_processing(client, ptypes, params);
		break;
	case PKCS11_CMD_DIGEST_INIT:
		rc = entry_processing_init(client, ptypes, params,
					   PKCS11_FUNCTION_DIGEST);
		break;
	case PKCS11_CMD_DIGEST_UPDATE:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DIGEST,
					   PKCS11_FUNC_STEP_UPDATE);
		break;
	case PKCS11_CMD_DIGEST_KEY:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DIGEST,
					   PKCS11_FUNC_STEP_UPDATE_KEY);
		break;
	case PKCS11_CMD_DIGEST_ONESHOT:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DIGEST,
					   PKCS11_FUNC_STEP_ONESHOT);
		break;
	case PKCS11_CMD_DIGEST_FINAL:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DIGEST,
					   PKCS11_FUNC_STEP_FINAL);
		break;
	case PKCS11_CMD_GENERATE_KEY_PAIR:
		rc = entry_generate_key_pair(client, ptypes, params);
		break;
	case PKCS11_CMD_WRAP_KEY:
		rc = entry_wrap_key(client, ptypes, params);
		break;
	case PKCS11_CMD_UNWRAP_KEY:
		rc = entry_processing_key(client, ptypes, params,
					  PKCS11_FUNCTION_UNWRAP);
		break;
	default:
		EMSG("Command %#"PRIx32" is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	DMSG("%s rc %#"PRIx32"/%s", id2str_ta_cmd(cmd), rc, id2str_rc(rc));

	TEE_MemMove(params[0].memref.buffer, &rc, sizeof(rc));
	params[0].memref.size = sizeof(rc);

	if (rc == PKCS11_CKR_BUFFER_TOO_SMALL)
		return TEE_ERROR_SHORT_BUFFER;
	else
		return TEE_SUCCESS;
}
