/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * 版权所有 (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_TA_H
#define PKCS11_TA_H

#include <stdbool.h>
#include <stdint.h>

#define PKCS11_TA_UUID { 0xfd02c9da, 0x306c, 0x48c7, \
			 { 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }

/* PKCS11 可信应用版本信息 */
#define PKCS11_TA_VERSION_MAJOR			1
#define PKCS11_TA_VERSION_MINOR			0
#define PKCS11_TA_VERSION_PATCH			0

/* 属性特定值 */
#define PKCS11_CK_UNAVAILABLE_INFORMATION	UINT32_C(0xFFFFFFFF)
#define PKCS11_UNDEFINED_ID			UINT32_C(0xFFFFFFFF)
#define PKCS11_FALSE				false
#define PKCS11_TRUE				true

/*
 * 关于 PKCS#11 TA 命令 ABI 的说明
 *
 * 为了 TA API 的演进并且不违反 GPD TEE 4 参数约束，所有 PKCS11 TA 调用命令
 * 使用可用的 GPD TEE 调用参数类型的子集。
 *
 * Param#0 用于被调用命令的所谓控制参数，并为请求命令提供符合 PKCS#11 的
 * 状态码。Param#0 是一个输入/输出内存引用（即 memref[0]）。输入缓冲区
 * 存储命令的序列化参数。输出缓冲区存储命令的 32 位 TA 返回码。因此，
 * param#0 应始终是至少 32 位的输入/输出内存引用，如果命令期望更多输入
 * 参数则更多。
 *
 * 当 TA 返回 TEE_SUCCESS 结果时，客户端应始终获取存储在 param#0 输出缓冲区
 * 中的 32 位值，并将该值用作被调用命令的 TA 返回码。
 *
 * Param#1 可用于被调用命令的输入数据参数。
 * 它未使用或是输入内存引用，即 memref[1]。
 * API 的演进可能也会将 memref[1] 用于输出数据。
 *
 * Param#2 主要用于被调用命令的输出数据参数和从被调用命令生成的输出句柄。
 * 少数命令将其用于辅助输入数据缓冲区参数。
 * 它未使用或是输入/输出/输入输出内存引用，即 memref[2]。
 *
 * Param#3 目前未使用，保留用于 API 的演进。
 */

enum pkcs11_ta_cmd {
	/*
	 * PKCS11_CMD_PING		确认 TA 存在并返回版本信息
	 *
	 * [in]  memref[0] = 32位，未使用，必须为 0
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = [
	 *              32位主版本号，
	 *              32位次版本号，
	 *              32位补丁版本号
	 *       ]
	 */
	PKCS11_CMD_PING = 0,

	/*
	 * PKCS11_CMD_SLOT_LIST - 获取有效插槽 ID 的表
	 *
	 * [in]  memref[0] = 32位，未使用，必须为 0
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 32位数组 slot_ids[插槽数量]
	 *
	 * TA 实例可能代表多个 PKCS#11 插槽和相关令牌。
	 * 此命令报告嵌入式令牌的 ID。
	 * 此命令对应 PKCS#11 API 函数 C_GetSlotList()。
	 */
	PKCS11_CMD_SLOT_LIST = 1,

	/*
	 * PKCS11_CMD_SLOT_INFO - 获取 cryptoki 结构化插槽信息
	 *
	 * [in]	 memref[0] = 32位插槽 ID
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_slot_info)info
	 *
	 * TA 实例可能代表多个 PKCS#11 插槽/令牌。
	 * 此命令对应 PKCS#11 API 函数 C_GetSlotInfo()。
	 */
	PKCS11_CMD_SLOT_INFO = 2,

	/*
	 * PKCS11_CMD_TOKEN_INFO - 获取 cryptoki 结构化令牌信息
	 *
	 * [in]	 memref[0] = 32位插槽 ID
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_token_info)info
	 *
	 * TA 实例可能代表多个 PKCS#11 插槽/令牌。
	 * 此命令对应 PKCS#11 API 函数 C_GetTokenInfo()。
	 */
	PKCS11_CMD_TOKEN_INFO = 3,

	/*
	 * PKCS11_CMD_MECHANISM_IDS - 获取支持的机制列表
	 *
	 * [in]	 memref[0] = 32位插槽 ID
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 32位数组机制 ID
	 *
	 * 此命令对应 PKCS#11 API 函数
	 * C_GetMechanismList()。
	 */
	PKCS11_CMD_MECHANISM_IDS = 4,

	/*
	 * PKCS11_CMD_MECHANISM_INFO - 获取特定机制的信息
	 *
	 * [in]  memref[0] = [
	 *              32位插槽 ID，
	 *              32位机制 ID (PKCS11_CKM_*)
	 *       ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_mechanism_info)info
	 *
	 * 此命令对应 PKCS#11 API 函数
	 * C_GetMechanismInfo()。
	 */
	PKCS11_CMD_MECHANISM_INFO = 5,

	/*
	 * PKCS11_CMD_OPEN_SESSION - 打开会话
	 *
	 * [in]  memref[0] = [
	 *              32位插槽 ID，
	 *              32位会话标志，
	 *       ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 32位会话句柄
	 *
	 * 此命令对应 PKCS#11 API 函数 C_OpenSession()。
	 */
	PKCS11_CMD_OPEN_SESSION = 6,

	/*
	 * PKCS11_CMD_CLOSE_SESSION - 关闭已打开的会话
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_CloseSession()。
	 */
	PKCS11_CMD_CLOSE_SESSION = 7,

	/*
	 * PKCS11_CMD_CLOSE_ALL_SESSIONS - 关闭令牌上的所有客户端会话
	 *
	 * [in]	 memref[0] = 32位插槽 ID
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数
	 * C_CloseAllSessions()。
	 */
	PKCS11_CMD_CLOSE_ALL_SESSIONS = 8,

	/*
	 * PKCS11_CMD_SESSION_INFO - 获取会话的 Cryptoki 信息
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_session_info)info
	 *
	 * 此命令对应 PKCS#11 API 函数 C_GetSessionInfo()。
	 */
	PKCS11_CMD_SESSION_INFO = 9,

	/*
	 * PKCS11_CMD_INIT_TOKEN - 初始化 PKCS#11 令牌
	 *
	 * [in]  memref[0] = [
	 *              32位插槽 ID，
	 *              32位 PIN 长度，
	 *              字节数组 label[32]，
	 *              字节数组 PIN[PIN 长度]，
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_InitToken()。
	 */
	PKCS11_CMD_INIT_TOKEN = 10,

	/*
	 * PKCS11_CMD_INIT_PIN - 初始化用户 PIN
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位 PIN 字节大小，
	 *              字节数组：PIN 数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_InitPIN()。
	 */
	PKCS11_CMD_INIT_PIN = 11,

	/*
	 * PKCS11_CMD_SET_PIN - 更改用户 PIN
	 *
	 * [in]	 memref[0] = [
	 *              32位会话句柄，
	 *              32位旧 PIN 字节大小，
	 *              32位新 PIN 字节大小，
	 *              字节数组：PIN 数据，
	 *              字节数组：新 PIN 数据，
	 *       ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_SetPIN()。
	 */
	PKCS11_CMD_SET_PIN = 12,

	/*
	 * PKCS11_CMD_LOGIN - 用户登录
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位用户标识符，枚举 pkcs11_user_type，
	 *              32位 PIN 字节大小，
	 *              字节数组：PIN 数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_Login()。
	 */
	PKCS11_CMD_LOGIN = 13,

	/*
	 * PKCS11_CMD_LOGOUT - 从令牌登出
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_Logout()。
	 */
	PKCS11_CMD_LOGOUT = 14,

	/*
	 * PKCS11_CMD_CREATE_OBJECT - 在会话或令牌中创建原始客户端组装对象
	 *
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              (struct pkcs11_object_head)attribs + 属性数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 32位对象句柄
	 *
	 * 此命令对应 PKCS#11 API 函数 C_CreateObject()。
	 */
	PKCS11_CMD_CREATE_OBJECT = 15,

	/*
	 * PKCS11_CMD_DESTROY_OBJECT - 销毁对象
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位对象句柄
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_DestroyObject()。
	 */
	PKCS11_CMD_DESTROY_OBJECT = 16,

	/*
	 * PKCS11_CMD_ENCRYPT_INIT - 初始化加密处理
	 * PKCS11_CMD_DECRYPT_INIT - 初始化解密处理
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位密钥的对象句柄，
	 *              (struct pkcs11_attribute_head)mechanism + 机制参数
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 这些命令对应 PKCS#11 API 函数
	 * C_EncryptInit() 和 C_DecryptInit()。
	 */
	PKCS11_CMD_ENCRYPT_INIT = 17,
	PKCS11_CMD_DECRYPT_INIT = 18,

	/*
	 * PKCS11_CMD_ENCRYPT_UPDATE - 更新加密处理
	 * PKCS11_CMD_DECRYPT_UPDATE - 更新解密处理
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [in]  memref[1] = 要处理的输入数据
	 * [out] memref[2] = 输出处理后的数据
	 *
	 * 这些命令对应 PKCS#11 API 函数
	 * C_EncryptUpdate() 和 C_DecryptUpdate()。
	 */
	PKCS11_CMD_ENCRYPT_UPDATE = 19,
	PKCS11_CMD_DECRYPT_UPDATE = 20,

	/*
	 * PKCS11_CMD_ENCRYPT_FINAL - 完成加密处理
	 * PKCS11_CMD_DECRYPT_FINAL - 完成解密处理
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 输出处理后的数据
	 *
	 * 这些命令对应 PKCS#11 API 函数
	 * C_EncryptFinal() 和 C_DecryptFinal()。
	 */
	PKCS11_CMD_ENCRYPT_FINAL = 21,
	PKCS11_CMD_DECRYPT_FINAL = 22,

	/*
	 * PKCS11_CMD_ENCRYPT_ONESHOT - 一次性更新并完成加密处理
	 *
	 * PKCS11_CMD_DECRYPT_ONESHOT - 一次性更新并完成解密处理
	 *
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [in]  memref[1] = 要处理的输入数据
	 * [out] memref[2] = 输出处理后的数据
	 *
	 * 这些命令对应 PKCS#11 API 函数 C_Encrypt 和
	 * C_Decrypt。
	 */
	PKCS11_CMD_ENCRYPT_ONESHOT = 23,
	PKCS11_CMD_DECRYPT_ONESHOT = 24,

	/*
	 * PKCS11_CMD_SIGN_INIT   - 初始化签名计算处理
	 *
	 * PKCS11_CMD_VERIFY_INIT - 初始化签名验证处理
	 *
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位密钥句柄，
	 *              (struct pkcs11_attribute_head)mechanism +
	 *                                            机制参数，
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 这些命令对应 PKCS#11 API 函数 C_SignInit() 和
	 * C_VerifyInit()。
	 */
	PKCS11_CMD_SIGN_INIT = 25,
	PKCS11_CMD_VERIFY_INIT = 26,

	/*
	 * PKCS11_CMD_SIGN_UPDATE   - 更新签名计算处理
	 * PKCS11_CMD_VERIFY_UPDATE - 更新签名验证处理
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [in]  memref[1] = 要处理的输入数据
	 *
	 * 这些命令对应 PKCS#11 API 函数 C_SignUpdate() 和
	 * C_VerifyUpdate()。
	 */
	PKCS11_CMD_SIGN_UPDATE = 27,
	PKCS11_CMD_VERIFY_UPDATE = 28,

	/*
	 * PKCS11_CMD_SIGN_FINAL - 完成签名计算处理
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 输出签名
	 *
	 * 此命令对应 PKCS#11 API 函数 C_SignFinal()。
	 */
	PKCS11_CMD_SIGN_FINAL = 29,

	/*
	 * PKCS11_CMD_VERIFY_FINAL - 完成签名验证处理
	 *
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [in]  memref[2] = 要处理的输入签名
	 *
	 * 此命令对应 PKCS#11 API 函数 C_VerifyFinal()。
	 */
	PKCS11_CMD_VERIFY_FINAL = 30,

	/*
	 * PKCS11_CMD_SIGN_ONESHOT - 一次性计算签名
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [in]  memref[1] = 要处理的输入数据
	 * [out] memref[2] = 字节数组：生成的签名
	 *
	 * 此命令对应 PKCS#11 API 函数 C_Sign()。
	 */
	PKCS11_CMD_SIGN_ONESHOT = 31,

	/*
	 * PKCS11_CMD_VERIFY_ONESHOT - 一次性计算并比较签名
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [in]  memref[1] = 要处理的输入数据
	 * [in]  memref[2] = 要处理的输入签名
	 *
	 * 此命令对应 PKCS#11 API 函数 C_Verify()。
	 */
	PKCS11_CMD_VERIFY_ONESHOT = 32,

	/*
	 * PKCS11_CMD_GENERATE_KEY - 生成对称密钥或域参数
	 *
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              (struct pkcs11_attribute_head)mechanism + 机制参数，
	 *              (struct pkcs11_object_head)attribs + 属性数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 32位对象句柄
	 *
	 * 此命令对应 PKCS#11 API 函数 C_GenerateKey()。
	 */
	PKCS11_CMD_GENERATE_KEY = 33,

	/*
	 * PKCS11_CMD_FIND_OBJECTS_INIT - 初始化对象搜索
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              (struct pkcs11_object_head)attribs + 属性数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_FindOjectsInit()。
	 */
	PKCS11_CMD_FIND_OBJECTS_INIT = 34,

	/*
	 * PKCS11_CMD_FIND_OBJECTS - 获取匹配对象的句柄
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 32位数组 object_handle_array[N]
	 *
	 * 此命令对应 PKCS#11 API 函数 C_FindOjects()。
	 * object_handle_array 的大小取决于客户端提供的输出缓冲区大小。
	 *
	 */
	PKCS11_CMD_FIND_OBJECTS = 35,

	/*
	 * PKCS11_CMD_FIND_OBJECTS_FINAL - 完成当前对象搜索
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_FindOjectsFinal()。
	 */
	PKCS11_CMD_FIND_OBJECTS_FINAL = 36,

	/*
	 * PKCS11_CMD_GET_OBJECT_SIZE - 获取 TEE 中对象使用的字节大小
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位对象句柄
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 32位 object_byte_size
	 *
	 * 此命令对应 PKCS#11 API 函数 C_GetObjectSize()。
	 */
	PKCS11_CMD_GET_OBJECT_SIZE = 37,

	/*
	 * PKCS11_CMD_GET_ATTRIBUTE_VALUE - 获取对象属性的值
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位对象句柄，
	 *              (struct pkcs11_object_head)attribs + 属性数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_object_head)attribs + 属性
	 *                   数据
	 *
	 * 此命令对应 PKCS#11 API 函数 C_GetAttributeValue。
	 * 调用者在 memref[0] 中提供属性模板作为第 3 个参数
	 * （此处称为 attribs + 属性数据）。成功完成后，
	 * TA 通过输出参数 memref[2] 返回填充了预期数据的
	 * 提供的模板（此处再次称为 attribs + 属性数据）。
	 */
	PKCS11_CMD_GET_ATTRIBUTE_VALUE = 38,

	/*
	 * PKCS11_CMD_SET_ATTRIBUTE_VALUE - 设置对象属性的值
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位对象句柄，
	 *              (struct pkcs11_object_head)attribs + 属性数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_SetAttributeValue。
	 * 调用者在 memref[0] 中提供属性模板作为第 3 个参数
	 * （此处称为 attribs + 属性数据）。
	 */
	PKCS11_CMD_SET_ATTRIBUTE_VALUE = 39,

	/*
	 * PKCS11_CMD_COPY_OBJECT - 复制对象，为副本创建新对象
	 *
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位对象句柄，
	 *              (struct pkcs11_object_head)attribs + 属性数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 32位对象句柄
	 *
	 * 此命令对应 PKCS#11 API 函数 C_CopyObject()。
	 * 调用者在 memref[0] 中提供属性模板作为第 3 个参数
	 * （此处称为 attribs + 属性数据）。
	 */
	PKCS11_CMD_COPY_OBJECT = 40,

	/*
	 * PKCS11_CMD_SEED_RANDOM - 为随机数据生成器提供种子
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [in]  memref[1] = 字节数组：输入到 RNG 的种子材料
	 *
	 * 此命令对应 PKCS#11 API 函数 C_SeedRandom()。
	 */
	PKCS11_CMD_SEED_RANDOM = 41,

	/*
	 * PKCS11_CMD_GENERATE_RANDOM - 生成随机数据
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 字节数组：生成的随机数
	 *
	 * 此命令对应 PKCS#11 API 函数 C_GenerateRandom()。
	 */
	PKCS11_CMD_GENERATE_RANDOM = 42,

	/*
	 * PKCS11_CMD_DERIVE_KEY - 从父密钥派生密钥
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位父密钥句柄，
	 *              (struct pkcs11_attribute_head)mechanism + 机制参数，
	 *              (struct pkcs11_object_head)attribs + 属性数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 32位对象句柄
	 *
	 * 此命令对应 PKCS#11 API 函数 C_DeriveKey()。
	 */
	PKCS11_CMD_DERIVE_KEY = 43,

	/*
	 * PKCS11_CMD_RELEASE_ACTIVE_PROCESSING - 释放活动处理
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位枚举 pkcs11_ta_cmd
	 *       ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令用于在用户空间处理中检测到 Cryptoki API 调用错误时
	 * 释放活动处理。从 pkcs11_ta_cmd 派生的函数用于验证活动
	 * 处理是否匹配。
	 */
	PKCS11_CMD_RELEASE_ACTIVE_PROCESSING = 44,

	/*
	 * PKCS11_CMD_DIGEST_INIT - 初始化摘要计算处理
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              (struct pkcs11_attribute_head)mechanism + 机制参数
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_DigestInit()。
	 */
	PKCS11_CMD_DIGEST_INIT = 45,

	/*
	 * PKCS11_CMD_DIGEST_KEY - 使用密钥更新摘要
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位密钥句柄
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 *
	 * 此命令对应 PKCS#11 API 函数 C_DigestKey()。
	 */
	PKCS11_CMD_DIGEST_KEY = 46,

	/*
	 * PKCS11_CMD_DIGEST_UPDATE - 使用数据更新摘要
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [in]  memref[1] = 要处理的输入数据
	 *
	 * 此命令对应 PKCS#11 API 函数 C_DigestUpdate()。
	 */
	PKCS11_CMD_DIGEST_UPDATE = 47,

	/*
	 * PKCS11_CMD_DIGEST_FINAL - 完成摘要计算处理
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 输出摘要
	 *
	 * 此命令对应 PKCS#11 API 函数 C_DigestFinal()。
	 */
	PKCS11_CMD_DIGEST_FINAL = 48,

	/*
	 * PKCS11_CMD_DIGEST_ONESHOT - 一次性计算摘要
	 *
	 * [in]  memref[0] = 32位会话句柄
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [in]  memref[1] = 要处理的输入数据
	 * [out] memref[2] = 字节数组：生成的摘要
	 *
	 * 此命令对应 PKCS#11 API 函数 C_Digest()。
	 */
	PKCS11_CMD_DIGEST_ONESHOT = 49,

	/*
	 * PKCS11_CMD_GENERATE_KEY_PAIR - 生成非对称密钥对
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              (struct pkcs11_attribute_head)mechanism + 机制参数，
	 *              (struct pkcs11_object_head)公钥属性 +
	 *              属性数据，
	 *              (struct pkcs11_object_head)私钥属性 +
	 *              属性数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = [
	 *              32位公钥对象句柄，
	 *              32位私钥对象句柄
	 *	 ]
	 *
	 * 此命令对应 PKCS#11 API 函数
	 * C_GenerateKeyPair()。
	 */
	PKCS11_CMD_GENERATE_KEY_PAIR = 50,

	/*
	 * PKCS11_CMD_WRAP_KEY - 包装私钥或密钥
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位包装密钥句柄，
	 *              32位密钥句柄，
	 *              (struct pkcs11_attribute_head)mechanism + 机制参数
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [out] memref[2] = 已包装的密钥
	 *
	 * 此命令对应 PKCS#11 API 函数 C_WrapKey()。
	 */
	PKCS11_CMD_WRAP_KEY = 51,

	/*
	 * PKCS11_CMD_UNWRAP_KEY - 解包已包装的密钥，创建新的
	 *                         私钥或密钥对象
	 *
	 * [in]  memref[0] = [
	 *              32位会话句柄，
	 *              32位解包密钥句柄，
	 *              (struct pkcs11_attribute_head)mechanism + 机制参数，
	 *              (struct pkcs11_object_head)attribs + 属性数据
	 *	 ]
	 * [out] memref[0] = 32位返回码，枚举 pkcs11_rc
	 * [in]  memref[1] = 已包装的密钥
	 * [out] memref[2] = 32位对象句柄
	 *
	 * 此命令对应 PKCS#11 API 函数 C_UnwrapKey()。
	 */
	PKCS11_CMD_UNWRAP_KEY = 52,
};

/*
 * 命令返回码
 * PKCS11_<x> 对应 CryptoKi 客户端 API CKR_<x>
 */
enum pkcs11_rc {
	PKCS11_CKR_OK				= 0,
	PKCS11_CKR_CANCEL			= 0x0001,
	PKCS11_CKR_SLOT_ID_INVALID		= 0x0003,
	PKCS11_CKR_GENERAL_ERROR		= 0x0005,
	PKCS11_CKR_FUNCTION_FAILED		= 0x0006,
	PKCS11_CKR_ARGUMENTS_BAD		= 0x0007,
	PKCS11_CKR_ATTRIBUTE_READ_ONLY		= 0x0010,
	PKCS11_CKR_ATTRIBUTE_SENSITIVE		= 0x0011,
	PKCS11_CKR_ATTRIBUTE_TYPE_INVALID	= 0x0012,
	PKCS11_CKR_ATTRIBUTE_VALUE_INVALID	= 0x0013,
	PKCS11_CKR_ACTION_PROHIBITED		= 0x001b,
	PKCS11_CKR_DATA_INVALID			= 0x0020,
	PKCS11_CKR_DATA_LEN_RANGE		= 0x0021,
	PKCS11_CKR_DEVICE_ERROR			= 0x0030,
	PKCS11_CKR_DEVICE_MEMORY		= 0x0031,
	PKCS11_CKR_DEVICE_REMOVED		= 0x0032,
	PKCS11_CKR_ENCRYPTED_DATA_INVALID	= 0x0040,
	PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE	= 0x0041,
	PKCS11_CKR_KEY_HANDLE_INVALID		= 0x0060,
	PKCS11_CKR_KEY_SIZE_RANGE		= 0x0062,
	PKCS11_CKR_KEY_TYPE_INCONSISTENT	= 0x0063,
	PKCS11_CKR_KEY_INDIGESTIBLE		= 0x0067,
	PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED	= 0x0068,
	PKCS11_CKR_KEY_NOT_WRAPPABLE		= 0x0069,
	PKCS11_CKR_KEY_UNEXTRACTABLE		= 0x006a,
	PKCS11_CKR_MECHANISM_INVALID		= 0x0070,
	PKCS11_CKR_MECHANISM_PARAM_INVALID	= 0x0071,
	PKCS11_CKR_OBJECT_HANDLE_INVALID	= 0x0082,
	PKCS11_CKR_OPERATION_ACTIVE		= 0x0090,
	PKCS11_CKR_OPERATION_NOT_INITIALIZED	= 0x0091,
	PKCS11_CKR_PIN_INCORRECT		= 0x00a0,
	PKCS11_CKR_PIN_INVALID			= 0x00a1,
	PKCS11_CKR_PIN_LEN_RANGE		= 0x00a2,
	PKCS11_CKR_PIN_EXPIRED			= 0x00a3,
	PKCS11_CKR_PIN_LOCKED			= 0x00a4,
	PKCS11_CKR_SESSION_CLOSED		= 0x00b0,
	PKCS11_CKR_SESSION_COUNT		= 0x00b1,
	PKCS11_CKR_SESSION_HANDLE_INVALID	= 0x00b3,
	PKCS11_CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x00b4,
	PKCS11_CKR_SESSION_READ_ONLY		= 0x00b5,
	PKCS11_CKR_SESSION_EXISTS		= 0x00b6,
	PKCS11_CKR_SESSION_READ_ONLY_EXISTS	= 0x00b7,
	PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS	= 0x00b8,
	PKCS11_CKR_SIGNATURE_INVALID		= 0x00c0,
	PKCS11_CKR_SIGNATURE_LEN_RANGE		= 0x00c1,
	PKCS11_CKR_TEMPLATE_INCOMPLETE		= 0x00d0,
	PKCS11_CKR_TEMPLATE_INCONSISTENT	= 0x00d1,
	PKCS11_CKR_TOKEN_NOT_PRESENT		= 0x00e0,
	PKCS11_CKR_TOKEN_NOT_RECOGNIZED		= 0x00e1,
	PKCS11_CKR_TOKEN_WRITE_PROTECTED	= 0x00e2,
	PKCS11_CKR_UNWRAPPING_KEY_HANDLE_INVALID = 0x00f0,
	PKCS11_CKR_UNWRAPPING_KEY_SIZE_RANGE	= 0x00f1,
	PKCS11_CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x00f2,
	PKCS11_CKR_USER_ALREADY_LOGGED_IN	= 0x0100,
	PKCS11_CKR_USER_NOT_LOGGED_IN		= 0x0101,
	PKCS11_CKR_USER_PIN_NOT_INITIALIZED	= 0x0102,
	PKCS11_CKR_USER_TYPE_INVALID		= 0x0103,
	PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x0104,
	PKCS11_CKR_USER_TOO_MANY_TYPES		= 0x0105,
	PKCS11_CKR_WRAPPED_KEY_INVALID		= 0x0110,
	PKCS11_CKR_WRAPPED_KEY_LEN_RANGE	= 0x0112,
	PKCS11_CKR_WRAPPING_KEY_HANDLE_INVALID  = 0x0113,
	PKCS11_CKR_WRAPPING_KEY_SIZE_RANGE	= 0x0114,
	PKCS11_CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x0115,
	PKCS11_CKR_RANDOM_SEED_NOT_SUPPORTED	= 0x0120,
	PKCS11_CKR_RANDOM_NO_RNG		= 0x0121,
	PKCS11_CKR_DOMAIN_PARAMS_INVALID	= 0x0130,
	PKCS11_CKR_CURVE_NOT_SUPPORTED		= 0x0140,
	PKCS11_CKR_BUFFER_TOO_SMALL		= 0x0150,
	PKCS11_CKR_SAVED_STATE_INVALID		= 0x0160,
	PKCS11_CKR_INFORMATION_SENSITIVE	= 0x0170,
	PKCS11_CKR_STATE_UNSAVEABLE		= 0x0180,
	PKCS11_CKR_PIN_TOO_WEAK			= 0x01b8,
	PKCS11_CKR_PUBLIC_KEY_INVALID		= 0x01b9,
	PKCS11_CKR_FUNCTION_REJECTED		= 0x0200,
	/* 供应商特定 ID，不返回给客户端 */
	PKCS11_RV_NOT_FOUND			= 0x80000000,
	PKCS11_RV_NOT_IMPLEMENTED		= 0x80000001,
};

/*
 * PKCS11_CMD_SLOT_INFO 的参数
 */
#define PKCS11_SLOT_DESC_SIZE			64
#define PKCS11_SLOT_MANUFACTURER_SIZE		32
#define PKCS11_SLOT_VERSION_SIZE		2

struct pkcs11_slot_info {
	uint8_t slot_description[PKCS11_SLOT_DESC_SIZE];
	uint8_t manufacturer_id[PKCS11_SLOT_MANUFACTURER_SIZE];
	uint32_t flags;
	uint8_t hardware_version[PKCS11_SLOT_VERSION_SIZE];
	uint8_t firmware_version[PKCS11_SLOT_VERSION_SIZE];
};

/*
 * pkcs11_slot_info::flags 的值。
 * PKCS11_CKFS_<x> 对应 CryptoKi 客户端 API 插槽标志 CKF_<x>。
 */
#define PKCS11_CKFS_TOKEN_PRESENT		(1U << 0)
#define PKCS11_CKFS_REMOVABLE_DEVICE		(1U << 1)
#define PKCS11_CKFS_HW_SLOT			(1U << 2)

/*
 * PKCS11_CMD_TOKEN_INFO 的参数
 */
#define PKCS11_TOKEN_LABEL_SIZE			32
#define PKCS11_TOKEN_MANUFACTURER_SIZE		32
#define PKCS11_TOKEN_MODEL_SIZE			16
#define PKCS11_TOKEN_SERIALNUM_SIZE		16

struct pkcs11_token_info {
	uint8_t label[PKCS11_TOKEN_LABEL_SIZE];
	uint8_t manufacturer_id[PKCS11_TOKEN_MANUFACTURER_SIZE];
	uint8_t model[PKCS11_TOKEN_MODEL_SIZE];
	uint8_t serial_number[PKCS11_TOKEN_SERIALNUM_SIZE];
	uint32_t flags;
	uint32_t max_session_count;
	uint32_t session_count;
	uint32_t max_rw_session_count;
	uint32_t rw_session_count;
	uint32_t max_pin_len;
	uint32_t min_pin_len;
	uint32_t total_public_memory;
	uint32_t free_public_memory;
	uint32_t total_private_memory;
	uint32_t free_private_memory;
	uint8_t hardware_version[2];
	uint8_t firmware_version[2];
	uint8_t utc_time[16];
};

/*
 * pkcs11_token_info::flags 的值。
 * PKCS11_CKFT_<x> 对应 CryptoKi 客户端 API 令牌标志 CKF_<x>。
 */
#define PKCS11_CKFT_RNG					(1U << 0)
#define PKCS11_CKFT_WRITE_PROTECTED			(1U << 1)
#define PKCS11_CKFT_LOGIN_REQUIRED			(1U << 2)
#define PKCS11_CKFT_USER_PIN_INITIALIZED		(1U << 3)
#define PKCS11_CKFT_RESTORE_KEY_NOT_NEEDED		(1U << 5)
#define PKCS11_CKFT_CLOCK_ON_TOKEN			(1U << 6)
#define PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH	(1U << 8)
#define PKCS11_CKFT_DUAL_CRYPTO_OPERATIONS		(1U << 9)
#define PKCS11_CKFT_TOKEN_INITIALIZED			(1U << 10)
#define PKCS11_CKFT_SECONDARY_AUTHENTICATION		(1U << 11)
#define PKCS11_CKFT_USER_PIN_COUNT_LOW			(1U << 16)
#define PKCS11_CKFT_USER_PIN_FINAL_TRY			(1U << 17)
#define PKCS11_CKFT_USER_PIN_LOCKED			(1U << 18)
#define PKCS11_CKFT_USER_PIN_TO_BE_CHANGED		(1U << 19)
#define PKCS11_CKFT_SO_PIN_COUNT_LOW			(1U << 20)
#define PKCS11_CKFT_SO_PIN_FINAL_TRY			(1U << 21)
#define PKCS11_CKFT_SO_PIN_LOCKED			(1U << 22)
#define PKCS11_CKFT_SO_PIN_TO_BE_CHANGED		(1U << 23)
#define PKCS11_CKFT_ERROR_STATE				(1U << 24)

/* 用户身份的值 */
enum pkcs11_user_type {
	PKCS11_CKU_SO = 0x000,
	PKCS11_CKU_USER = 0x001,
	PKCS11_CKU_CONTEXT_SPECIFIC = 0x002,
};

/*
 * 令牌的基于 TEE 身份的身份验证
 *
 * 当启用配置 CFG_PKCS11_TA_AUTH_TEE_IDENTITY 时，启用基于 TEE 身份的
 * 身份验证方案。
 *
 * 按令牌启用功能由令牌标志控制：
 * pkcs11_token_info->flags & PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH
 *
 * 调用 C_InitToken() 时，模式根据 SO PIN 值确定。
 * - 如果 PIN 为空（或 NULL_PTR），则活动客户端 TEE 身份将用作
 *   SO TEE 身份
 * - 如果提供了 PIN，则使用正常的 PIN 行为
 *
 * 一旦激活基于 TEE 身份的身份验证，将发生以下操作更改：
 * - PIN 失败计数器被禁用以防止令牌身份验证锁定
 * - 执行 C_Login() 时，实际 PIN 值被忽略，并将使用活动
 *   客户端 TEE 身份
 *
 * 成功调用 C_InitToken() 后，可以切换身份验证模式，因为用户凭据
 * 已被清除。设置用户凭据后，身份验证模式切换将受到保护。
 *
 * 从 PIN 切换到 TEE 身份验证模式：
 * - 确保为 TA 连接设置了活动 TEE 身份
 * - 以 SO 身份登录，以便 PIN 更改影响 SO
 * - 使用空 PIN 调用 C_SetPIN() 以捕获当前 TEE 身份作为 SO
 *   凭据
 * - 可选：可以使用连续调用 C_SetPIN() 更改为相对于当前 TA 连接的
 *   其他 TEE 身份
 *
 * 从 TEE 身份切换到 PIN 身份验证模式：
 * - 确保为 TA 连接设置了 SO 的 TEE 身份
 * - 以 SO 身份登录，以便 PIN 更改影响 SO
 * - 使用任何与 TEE 身份 PIN 语法不匹配的 PIN 调用 C_SetPIN()
 * - 可选：如果与 TEE 身份 PIN 语法发生冲突，可以使用连续调用
 *   C_SetPIN() 将 SO 凭据更改为任何有效的 PIN
 *
 * 可以配置不同类型的 TEE 身份验证方法：
 * - 使用 C_InitToken()、C_InitPIN() 或 C_SetPIN() 配置
 * - PIN 值遵循以下 PIN 语法
 *
 * 基于 TEE 身份的身份验证 PIN 语法：
 * - PIN 值：NULL_PTR 或空
 *   - 使用活动客户端 TEE 身份
 * - PIN 值：public
 *   - TEE 公共登录
 * - PIN 值：user:<客户端 UUID 字符串>
 *   - TEE 用户登录，客户端 UUID 与用户凭据匹配
 * - PIN 值：group:<客户端 UUID 字符串>
 *   - TEE 组登录，客户端 UUID 与组凭据匹配
 */

/* 受保护身份验证路径 PIN 解析器的关键字 */
#define PKCS11_AUTH_TEE_IDENTITY_PUBLIC	"public"
#define PKCS11_AUTH_TEE_IDENTITY_USER	"user:"
#define PKCS11_AUTH_TEE_IDENTITY_GROUP	"group:"

/*
 * PKCS11_CMD_OPEN_SESSION 的 32 位会话标志参数的值
 * 和 pkcs11_session_info::flags。
 * PKCS11_CKFSS_<x> 对应 CryptoKi 客户端 API 会话标志 CKF_<x>。
 */
#define PKCS11_CKFSS_RW_SESSION				(1U << 1)
#define PKCS11_CKFSS_SERIAL_SESSION			(1U << 2)

/*
 * PKCS11_CMD_SESSION_INFO 的参数
 */

struct pkcs11_session_info {
	uint32_t slot_id;
	uint32_t state;
	uint32_t flags;
	uint32_t device_error;
};

/* pkcs11_session_info::state 的有效值 */
enum pkcs11_session_state {
	PKCS11_CKS_RO_PUBLIC_SESSION = 0,
	PKCS11_CKS_RO_USER_FUNCTIONS = 1,
	PKCS11_CKS_RW_PUBLIC_SESSION = 2,
	PKCS11_CKS_RW_USER_FUNCTIONS = 3,
	PKCS11_CKS_RW_SO_FUNCTIONS = 4,
};

/*
 * PKCS11_CMD_MECHANISM_INFO 的参数
 */

struct pkcs11_mechanism_info {
	uint32_t min_key_size;
	uint32_t max_key_size;
	uint32_t flags;
};

/*
 * pkcs11_mechanism_info::flags 的值。
 * PKCS11_CKFM_<x> 对应 CryptoKi 客户端 API 机制标志 CKF_<x>。
 */
#define PKCS11_CKFM_HW				(1U << 0)
#define PKCS11_CKFM_ENCRYPT			(1U << 8)
#define PKCS11_CKFM_DECRYPT			(1U << 9)
#define PKCS11_CKFM_DIGEST			(1U << 10)
#define PKCS11_CKFM_SIGN			(1U << 11)
#define PKCS11_CKFM_SIGN_RECOVER		(1U << 12)
#define PKCS11_CKFM_VERIFY			(1U << 13)
#define PKCS11_CKFM_VERIFY_RECOVER		(1U << 14)
#define PKCS11_CKFM_GENERATE			(1U << 15)
#define PKCS11_CKFM_GENERATE_KEY_PAIR		(1U << 16)
#define PKCS11_CKFM_WRAP			(1U << 17)
#define PKCS11_CKFM_UNWRAP			(1U << 18)
#define PKCS11_CKFM_DERIVE			(1U << 19)
#define PKCS11_CKFM_EC_F_P			(1U << 20)
#define PKCS11_CKFM_EC_F_2M			(1U << 21)
#define PKCS11_CKFM_EC_ECPARAMETERS		(1U << 22)
#define PKCS11_CKFM_EC_NAMEDCURVE		(1U << 23)
#define PKCS11_CKFM_EC_UNCOMPRESS		(1U << 24)
#define PKCS11_CKFM_EC_COMPRESS			(1U << 25)

/*
 * pkcs11_object_head - 数据在内存中序列化的对象头
 *
 * 对象由多个属性组成。属性作为序列化字节数组以字节对齐方式一个接一个
 * 地存储。序列化属性的字节数组前面带有 attrs[] 数组的字节大小和数组中
 * 的属性数量，从而产生结构 pkcs11_object_head。
 *
 * @attrs_size - 整个字节数组 attrs[] 的字节大小
 * @attrs_count - 存储在 attrs[] 中的属性项数
 * @attrs - 然后开始属性数据
 */
struct pkcs11_object_head {
	uint32_t attrs_size;
	uint32_t attrs_count;
	uint8_t attrs[];
};

/*
 * TA ABI 中的属性引用。每个属性以头结构开始，后跟属性值。
 * 属性字节大小在属性头中定义。
 *
 * @id - 属性的 32 位标识符，参见 PKCS11_CKA_<x>
 * @size - 32 位值属性字节大小
 * @data - 然后开始属性值
 */
struct pkcs11_attribute_head {
	uint32_t id;
	uint32_t size;
	uint8_t data[];
};

#define PKCS11_CKA_VENDOR_DEFINED	0x80000000UL

/**
 * PKCS11_CKF_ARRAY_ATTRIBUTE 标志标识由值数组组成的属性。
 */
#define PKCS11_CKF_ARRAY_ATTRIBUTE	0x40000000UL

/*
 * OP-TEE 的供应商特定 PKCS#11 属性分配
 *
 * 位 31 - PKCS11_CKA_VENDOR_DEFINED
 * 位 30 - PKCS11_CKF_ARRAY_ATTRIBUTE - 像普通属性中一样工作
 * 位 24-29 - 保留，以防 PKCS#11 标准开始使用它们
 * 位 16-23 - 分配给 OP-TEE 属性标志
 * 位 0-15 - 分配给属性标识符
 */

/* OP-TEE 属性标志 */

/**
 * 用于检查是否设置了 OP-TEE 属性标志的标志掩码。
 */
#define PKCS11_CKA_OPTEE_FLAGS_MASK	(PKCS11_CKA_VENDOR_DEFINED | \
					 0x00FF0000UL)

/**
 * PKCS11_CKA_OPTEE_FLAGS_HIDDEN 定义不会从 PKCS11 TA 导出到其客户端的
 * 属性。从客户端应用程序的角度来看，该属性不存在。
 */
#define PKCS11_CKA_OPTEE_FLAGS_HIDDEN	(PKCS11_CKA_VENDOR_DEFINED | \
					 0x00010000UL)

/*
 * 截至 v2.40 的属性标识 ID，不包括已弃用的 ID。
 * 结构 pkcs11_attribute_head::id 的有效值
 * PKCS11_CKA_<x> 对应 CryptoKi 客户端 API 属性 ID CKA_<x>。
 */
enum pkcs11_attr_id {
	PKCS11_CKA_CLASS			= 0x0000,
	PKCS11_CKA_TOKEN			= 0x0001,
	PKCS11_CKA_PRIVATE			= 0x0002,
	PKCS11_CKA_LABEL			= 0x0003,
	PKCS11_CKA_APPLICATION			= 0x0010,
	PKCS11_CKA_VALUE			= 0x0011,
	PKCS11_CKA_OBJECT_ID			= 0x0012,
	PKCS11_CKA_CERTIFICATE_TYPE		= 0x0080,
	PKCS11_CKA_ISSUER			= 0x0081,
	PKCS11_CKA_SERIAL_NUMBER		= 0x0082,
	PKCS11_CKA_AC_ISSUER			= 0x0083,
	PKCS11_CKA_OWNER			= 0x0084,
	PKCS11_CKA_ATTR_TYPES			= 0x0085,
	PKCS11_CKA_TRUSTED			= 0x0086,
	PKCS11_CKA_CERTIFICATE_CATEGORY		= 0x0087,
	PKCS11_CKA_JAVA_MIDP_SECURITY_DOMAIN	= 0x0088,
	PKCS11_CKA_URL				= 0x0089,
	PKCS11_CKA_HASH_OF_SUBJECT_PUBLIC_KEY	= 0x008a,
	PKCS11_CKA_HASH_OF_ISSUER_PUBLIC_KEY	= 0x008b,
	PKCS11_CKA_NAME_HASH_ALGORITHM		= 0x008c,
	PKCS11_CKA_CHECK_VALUE			= 0x0090,
	PKCS11_CKA_KEY_TYPE			= 0x0100,
	PKCS11_CKA_SUBJECT			= 0x0101,
	PKCS11_CKA_ID				= 0x0102,
	PKCS11_CKA_SENSITIVE			= 0x0103,
	PKCS11_CKA_ENCRYPT			= 0x0104,
	PKCS11_CKA_DECRYPT			= 0x0105,
	PKCS11_CKA_WRAP				= 0x0106,
	PKCS11_CKA_UNWRAP			= 0x0107,
	PKCS11_CKA_SIGN				= 0x0108,
	PKCS11_CKA_SIGN_RECOVER			= 0x0109,
	PKCS11_CKA_VERIFY			= 0x010a,
	PKCS11_CKA_VERIFY_RECOVER		= 0x010b,
	PKCS11_CKA_DERIVE			= 0x010c,
	PKCS11_CKA_START_DATE			= 0x0110,
	PKCS11_CKA_END_DATE			= 0x0111,
	PKCS11_CKA_MODULUS			= 0x0120,
	PKCS11_CKA_MODULUS_BITS			= 0x0121,
	PKCS11_CKA_PUBLIC_EXPONENT		= 0x0122,
	PKCS11_CKA_PRIVATE_EXPONENT		= 0x0123,
	PKCS11_CKA_PRIME_1			= 0x0124,
	PKCS11_CKA_PRIME_2			= 0x0125,
	PKCS11_CKA_EXPONENT_1			= 0x0126,
	PKCS11_CKA_EXPONENT_2			= 0x0127,
	PKCS11_CKA_COEFFICIENT			= 0x0128,
	PKCS11_CKA_PUBLIC_KEY_INFO		= 0x0129,
	PKCS11_CKA_PRIME			= 0x0130,
	PKCS11_CKA_SUBPRIME			= 0x0131,
	PKCS11_CKA_BASE				= 0x0132,
	PKCS11_CKA_PRIME_BITS			= 0x0133,
	PKCS11_CKA_SUBPRIME_BITS		= 0x0134,
	PKCS11_CKA_VALUE_BITS			= 0x0160,
	PKCS11_CKA_VALUE_LEN			= 0x0161,
	PKCS11_CKA_EXTRACTABLE			= 0x0162,
	PKCS11_CKA_LOCAL			= 0x0163,
	PKCS11_CKA_NEVER_EXTRACTABLE		= 0x0164,
	PKCS11_CKA_ALWAYS_SENSITIVE		= 0x0165,
	PKCS11_CKA_KEY_GEN_MECHANISM		= 0x0166,
	PKCS11_CKA_MODIFIABLE			= 0x0170,
	PKCS11_CKA_COPYABLE			= 0x0171,
	PKCS11_CKA_DESTROYABLE			= 0x0172,
	PKCS11_CKA_EC_PARAMS			= 0x0180,
	PKCS11_CKA_EC_POINT			= 0x0181,
	PKCS11_CKA_ALWAYS_AUTHENTICATE		= 0x0202,
	PKCS11_CKA_WRAP_WITH_TRUSTED		= 0x0210,
	PKCS11_CKA_WRAP_TEMPLATE		= PKCS11_CKF_ARRAY_ATTRIBUTE |
						  0x0211,
	PKCS11_CKA_UNWRAP_TEMPLATE		= PKCS11_CKF_ARRAY_ATTRIBUTE |
						  0x0212,
	PKCS11_CKA_DERIVE_TEMPLATE		= PKCS11_CKF_ARRAY_ATTRIBUTE |
						  0x0213,
	PKCS11_CKA_OTP_FORMAT			= 0x0220,
	PKCS11_CKA_OTP_LENGTH			= 0x0221,
	PKCS11_CKA_OTP_TIME_INTERVAL		= 0x0222,
	PKCS11_CKA_OTP_USER_FRIENDLY_MODE	= 0x0223,
	PKCS11_CKA_OTP_CHALLENGE_REQUIREMENT	= 0x0224,
	PKCS11_CKA_OTP_TIME_REQUIREMENT		= 0x0225,
	PKCS11_CKA_OTP_COUNTER_REQUIREMENT	= 0x0226,
	PKCS11_CKA_OTP_PIN_REQUIREMENT		= 0x0227,
	PKCS11_CKA_OTP_COUNTER			= 0x022e,
	PKCS11_CKA_OTP_TIME			= 0x022f,
	PKCS11_CKA_OTP_USER_IDENTIFIER		= 0x022a,
	PKCS11_CKA_OTP_SERVICE_IDENTIFIER	= 0x022b,
	PKCS11_CKA_OTP_SERVICE_LOGO		= 0x022c,
	PKCS11_CKA_OTP_SERVICE_LOGO_TYPE	= 0x022d,
	PKCS11_CKA_GOSTR3410_PARAMS		= 0x0250,
	PKCS11_CKA_GOSTR3411_PARAMS		= 0x0251,
	PKCS11_CKA_GOST28147_PARAMS		= 0x0252,
	PKCS11_CKA_HW_FEATURE_TYPE		= 0x0300,
	PKCS11_CKA_RESET_ON_INIT		= 0x0301,
	PKCS11_CKA_HAS_RESET			= 0x0302,
	PKCS11_CKA_PIXEL_X			= 0x0400,
	PKCS11_CKA_PIXEL_Y			= 0x0401,
	PKCS11_CKA_RESOLUTION			= 0x0402,
	PKCS11_CKA_CHAR_ROWS			= 0x0403,
	PKCS11_CKA_CHAR_COLUMNS			= 0x0404,
	PKCS11_CKA_COLOR			= 0x0405,
	PKCS11_CKA_BITS_PER_PIXEL		= 0x0406,
	PKCS11_CKA_CHAR_SETS			= 0x0480,
	PKCS11_CKA_ENCODING_METHODS		= 0x0481,
	PKCS11_CKA_MIME_TYPES			= 0x0482,
	PKCS11_CKA_MECHANISM_TYPE		= 0x0500,
	PKCS11_CKA_REQUIRED_CMS_ATTRIBUTES	= 0x0501,
	PKCS11_CKA_DEFAULT_CMS_ATTRIBUTES	= 0x0502,
	PKCS11_CKA_SUPPORTED_CMS_ATTRIBUTES	= 0x0503,
	PKCS11_CKA_ALLOWED_MECHANISMS		= PKCS11_CKF_ARRAY_ATTRIBUTE |
						  0x0600,

	/* 供应商特定属性 */

	/**
	 * TEE 内部 API 要求私钥操作可用 EC 公钥信息。
	 * 由于 EC 私钥对象不应包含 CKA_EC_POINT，因此包含
	 * 隐藏的对象，这样就不需要在每次操作时计算它。
	 */
	PKCS11_CKA_OPTEE_HIDDEN_EC_POINT = PKCS11_CKA_VENDOR_DEFINED |
					   PKCS11_CKA_OPTEE_FLAGS_HIDDEN |
					   0x0000,

	/* 供应商扩展：为未定义 ID (~0U) 保留 */
	PKCS11_CKA_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * 属性 PKCS11_CKA_CLASS 的有效值
 * PKCS11_CKO_<x> 对应 CryptoKi 客户端 API 对象类 ID CKO_<x>。
 */
enum pkcs11_class_id {
	PKCS11_CKO_DATA				= 0x000,
	PKCS11_CKO_CERTIFICATE			= 0x001,
	PKCS11_CKO_PUBLIC_KEY			= 0x002,
	PKCS11_CKO_PRIVATE_KEY			= 0x003,
	PKCS11_CKO_SECRET_KEY			= 0x004,
	PKCS11_CKO_HW_FEATURE			= 0x005,
	PKCS11_CKO_DOMAIN_PARAMETERS		= 0x006,
	PKCS11_CKO_MECHANISM			= 0x007,
	PKCS11_CKO_OTP_KEY			= 0x008,
	/* 供应商扩展：为未定义 ID (~0U) 保留 */
	PKCS11_CKO_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * 属性 PKCS11_CKA_KEY_TYPE 的有效值
 * PKCS11_CKK_<x> 对应 CryptoKi 客户端 API 密钥类型 ID CKK_<x>。
 * 注意，这只是 PKCS#11 规范的子集。
 */
enum pkcs11_key_type {
	PKCS11_CKK_RSA				= 0x000,
	PKCS11_CKK_DSA				= 0x001,
	PKCS11_CKK_DH				= 0x002,
	PKCS11_CKK_EC				= 0x003,
	PKCS11_CKK_EDDSA			= 0x004,
	PKCS11_CKK_GENERIC_SECRET		= 0x010,
	PKCS11_CKK_AES				= 0x01f,
	PKCS11_CKK_MD5_HMAC			= 0x027,
	PKCS11_CKK_SHA_1_HMAC			= 0x028,
	PKCS11_CKK_SHA256_HMAC			= 0x02b,
	PKCS11_CKK_SHA384_HMAC			= 0x02c,
	PKCS11_CKK_SHA512_HMAC			= 0x02d,
	PKCS11_CKK_SHA224_HMAC			= 0x02e,
	PKCS11_CKK_EC_EDWARDS			= 0x040,
	/* 供应商扩展：为未定义 ID (~0U) 保留 */
	PKCS11_CKK_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * 属性 PKCS11_CKA_CERTIFICATE_TYPE 的有效值
 */
enum pkcs11_certificate_type {
	PKCS11_CKC_X_509		= 0x00000000UL,
	PKCS11_CKC_X_509_ATTR_CERT	= 0x00000001UL,
	PKCS11_CKC_WTLS			= 0x00000002UL,
	/* 供应商扩展：为未定义 ID (~0U) 保留 */
	PKCS11_CKC_UNDEFINED_ID		= PKCS11_UNDEFINED_ID,
};

/*
 * 属性 PKCS11_CKA_CERTIFICATE_CATEGORY 的有效值
 */
enum pkcs11_certificate_category {
	PKCS11_CK_CERTIFICATE_CATEGORY_UNSPECIFIED	= 0UL,
	PKCS11_CK_CERTIFICATE_CATEGORY_TOKEN_USER	= 1UL,
	PKCS11_CK_CERTIFICATE_CATEGORY_AUTHORITY	= 2UL,
	PKCS11_CK_CERTIFICATE_CATEGORY_OTHER_ENTITY	= 3UL,
};

/*
 * 机制 ID 的有效值
 * PKCS11_CKM_<x> 对应 CryptoKi 客户端 API 机制 ID CKM_<x>。
 * 注意，这将根据需要进行扩展。
 */
enum pkcs11_mechanism_id {
	PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN	= 0x00000,
	PKCS11_CKM_RSA_PKCS			= 0x00001,
	PKCS11_CKM_RSA_X_509			= 0x00003,
	PKCS11_CKM_MD5_RSA_PKCS			= 0x00005,
	PKCS11_CKM_SHA1_RSA_PKCS		= 0x00006,
	PKCS11_CKM_RSA_PKCS_OAEP		= 0x00009,
	PKCS11_CKM_RSA_PKCS_PSS			= 0x0000d,
	PKCS11_CKM_SHA1_RSA_PKCS_PSS		= 0x0000e,
	PKCS11_CKM_SHA256_RSA_PKCS		= 0x00040,
	PKCS11_CKM_SHA384_RSA_PKCS		= 0x00041,
	PKCS11_CKM_SHA512_RSA_PKCS		= 0x00042,
	PKCS11_CKM_SHA256_RSA_PKCS_PSS		= 0x00043,
	PKCS11_CKM_SHA384_RSA_PKCS_PSS		= 0x00044,
	PKCS11_CKM_SHA512_RSA_PKCS_PSS		= 0x00045,
	PKCS11_CKM_SHA224_RSA_PKCS		= 0x00046,
	PKCS11_CKM_SHA224_RSA_PKCS_PSS		= 0x00047,
	PKCS11_CKM_MD5				= 0x00210,
	PKCS11_CKM_MD5_HMAC			= 0x00211,
	PKCS11_CKM_MD5_HMAC_GENERAL		= 0x00212,
	PKCS11_CKM_SHA_1			= 0x00220,
	PKCS11_CKM_SHA_1_HMAC			= 0x00221,
	PKCS11_CKM_SHA_1_HMAC_GENERAL		= 0x00222,
	PKCS11_CKM_SHA256			= 0x00250,
	PKCS11_CKM_SHA256_HMAC			= 0x00251,
	PKCS11_CKM_SHA256_HMAC_GENERAL		= 0x00252,
	PKCS11_CKM_SHA224			= 0x00255,
	PKCS11_CKM_SHA224_HMAC			= 0x00256,
	PKCS11_CKM_SHA224_HMAC_GENERAL		= 0x00257,
	PKCS11_CKM_SHA384			= 0x00260,
	PKCS11_CKM_SHA384_HMAC			= 0x00261,
	PKCS11_CKM_SHA384_HMAC_GENERAL		= 0x00262,
	PKCS11_CKM_SHA512			= 0x00270,
	PKCS11_CKM_SHA512_HMAC			= 0x00271,
	PKCS11_CKM_SHA512_HMAC_GENERAL		= 0x00272,
	PKCS11_CKM_GENERIC_SECRET_KEY_GEN	= 0x00350,
	PKCS11_CKM_EC_KEY_PAIR_GEN		= 0x01040,
	PKCS11_CKM_ECDSA			= 0x01041,
	PKCS11_CKM_ECDSA_SHA1			= 0x01042,
	PKCS11_CKM_ECDSA_SHA224			= 0x01043,
	PKCS11_CKM_ECDSA_SHA256			= 0x01044,
	PKCS11_CKM_ECDSA_SHA384			= 0x01045,
	PKCS11_CKM_ECDSA_SHA512			= 0x01046,
	PKCS11_CKM_ECDH1_DERIVE			= 0x01050,
	PKCS11_CKM_RSA_AES_KEY_WRAP		= 0x01054,
	PKCS11_CKM_EC_EDWARDS_KEY_PAIR_GEN	= 0x01055,
	PKCS11_CKM_EDDSA			= 0x01057,
	PKCS11_CKM_AES_KEY_GEN			= 0x01080,
	PKCS11_CKM_AES_ECB			= 0x01081,
	PKCS11_CKM_AES_CBC			= 0x01082,
	PKCS11_CKM_AES_CBC_PAD			= 0x01085,
	PKCS11_CKM_AES_CTR			= 0x01086,
	PKCS11_CKM_AES_GCM			= 0x01087,
	PKCS11_CKM_AES_CTS			= 0x01089,
	PKCS11_CKM_AES_CMAC			= 0x0108a,
	PKCS11_CKM_AES_CMAC_GENERAL		= 0x0108b,
	PKCS11_CKM_AES_ECB_ENCRYPT_DATA		= 0x01104,
	PKCS11_CKM_AES_CBC_ENCRYPT_DATA		= 0x01105,
	/*
	 * 以下是供应商扩展。
	 * PKCS11 为与 CK 机制 ID 无关的操作添加了 ID
	 */
	PKCS11_PROCESSING_IMPORT		= 0x80000000,
	PKCS11_CKM_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * PKCS11_CKD_<x> 对应 CryptoKi 客户端 API 密钥差分函数 ID CKD_<x>。
 */
enum pkcs11_keydiff_id {
	PKCS11_CKD_NULL				= 0x0001,
	/* 供应商扩展：为未定义 ID (~0U) 保留 */
	PKCS11_CKD_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * MG 函数标识符的有效值
 * PKCS11_CKG_<x> 对应 CryptoKi 客户端 API MG 函数 ID CKG_<x>。
 */
enum pkcs11_mgf_id {
	PKCS11_CKG_MGF1_SHA1			= 0x0001,
	PKCS11_CKG_MGF1_SHA224			= 0x0005,
	PKCS11_CKG_MGF1_SHA256			= 0x0002,
	PKCS11_CKG_MGF1_SHA384			= 0x0003,
	PKCS11_CKG_MGF1_SHA512			= 0x0004,
	/* 供应商扩展：为未定义 ID (~0U) 保留 */
	PKCS11_CKG_UNDEFINED_ID			= PKCS11_UNDEFINED_ID,
};

/*
 * RSA PKCS/OAEP 源类型标识符的有效值
 * PKCS11_CKZ_<x> 对应 CryptoKi 客户端 API 源类型 ID CKZ_<x>。
 */
#define PKCS11_CKZ_DATA_SPECIFIED		0x0001

#endif /*PKCS11_TA_H*/
