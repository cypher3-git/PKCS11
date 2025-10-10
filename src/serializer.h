/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

/*
 * ==============================================================================
 * 模块接口定义: 序列化工具 (Serializer)
 * ==============================================================================
 * 
 * 本头文件定义了REE与TEE之间数据序列化/反序列化的接口。
 * 
 * 【核心功能】
 * 1. 从客户端memref中解析参数（反序列化）
 * 2. 将TA数据打包到memref返回（序列化）
 * 3. 提供边界检查和溢出保护
 * 
 * 【数据流向】
 * 客户端 → TEE_Param.memref → serialargs → TA内部结构
 * TA内部结构 → serialize → TEE_Param.memref → 客户端
 * 
 * 【使用模式】
 * 1. 初始化: serialargs_init()
 * 2. 提取参数: serialargs_get*() 系列函数
 * 3. 验证完整: serialargs_remaining_bytes()
 */

#ifndef PKCS11_TA_SERIALIZER_H
#define PKCS11_TA_SERIALIZER_H

#include <pkcs11_ta.h>
#include <stdbool.h>
#include <stdint.h>

struct pkcs11_client;
struct pkcs11_session;

/*
 * 序列化参数解析器状态结构
 * 
 * 【字段说明】
 * @start: 缓冲区起始地址（不变，用于计算剩余字节）
 * @next:  当前读取位置（动态推进）
 * @size:  缓冲区总大小（不变）
 * 
 * 【状态追踪】
 * - 已读取字节数: next - start
 * - 剩余字节数:   (start + size) - next
 * 
 * 【典型用法】
 * struct serialargs args;
 * serialargs_init(&args, memref.buffer, memref.size);
 * serialargs_get_u32(&args, &param1);
 * serialargs_get(&args, &param2, sizeof(param2));
 * // 验证所有数据都已读取
 * if (serialargs_remaining_bytes(&args))
 *     return PKCS11_CKR_ARGUMENTS_BAD;
 */
struct serialargs {
	char *start;   /* 缓冲区起始地址 */
	char *next;    /* 当前读取位置 */
	size_t size;   /* 缓冲区总大小 */
};

struct pkcs11_client;
struct pkcs11_session;

/*
 * 初始化序列化参数解析器
 * 
 * @args: 序列化状态结构体
 * @in:   输入缓冲区（客户端传入的memref）
 * @size: 缓冲区大小
 * 
 * 功能：设置缓冲区起始位置、当前读取位置和总大小
 */
void serialargs_init(struct serialargs *args, void *in, size_t size);

/*
 * 从序列化缓冲区提取数据并复制到输出缓冲区
 * 
 * @args: 序列化状态结构体
 * @out:  输出缓冲区（调用者提供）
 * @sz:   要复制的字节数
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足
 * 
 * 功能：复制数据到调用者提供的缓冲区并推进读取位置
 */
enum pkcs11_rc serialargs_get(struct serialargs *args, void *out, size_t sz);

/*
 * 从序列化缓冲区提取32位无符号整数
 * 
 * @args: 序列化状态结构体
 * @out:  输出uint32_t指针
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足
 * 
 * 这是一个内联便捷函数，等价于 serialargs_get(args, out, 4)
 * 
 * 典型使用：
 *   uint32_t slot_id;
 *   rc = serialargs_get_u32(&args, &slot_id);
 */
static inline enum pkcs11_rc serialargs_get_u32(struct serialargs *args,
						uint32_t *out)
{
	return serialargs_get(args, out, sizeof(*out));
}

/*
 * 获取指向序列化数据的指针（零拷贝）
 * 
 * @args: 序列化状态结构体
 * @out:  返回指向缓冲区的指针
 * @size: 要访问的字节数
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足或溢出
 * 
 * 功能：返回指针并推进读取位置，不复制数据（高效）
 * 注意：指针指向原始缓冲区，生命周期与缓冲区相同
 */
enum pkcs11_rc serialargs_get_ptr(struct serialargs *args, void **out,
				  size_t size);

/*
 * 分配内存并提取单个属性
 * 
 * @args: 序列化状态结构体
 * @out:  返回分配的属性指针（调用者负责释放）
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足
 * - PKCS11_CKR_DEVICE_MEMORY: 内存分配失败
 * 
 * 功能：提取属性头和属性值，合并为完整属性结构
 */
enum pkcs11_rc
serialargs_alloc_get_one_attribute(struct serialargs *args,
				   struct pkcs11_attribute_head **out);

/*
 * 分配内存并提取对象属性列表
 * 
 * @args: 序列化状态结构体
 * @out:  返回分配的对象头指针（调用者负责释放）
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足
 * - PKCS11_CKR_DEVICE_MEMORY: 内存分配失败
 * 
 * 功能：提取对象头和所有属性数据，合并为完整对象
 */
enum pkcs11_rc serialargs_alloc_get_attributes(struct serialargs *args,
					       struct pkcs11_object_head **out);

/*
 * 分配内存并提取任意数据
 * 
 * @args: 序列化状态结构体
 * @out:  返回分配的内存指针（调用者负责释放）
 * @size: 要提取的字节数
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足
 * - PKCS11_CKR_DEVICE_MEMORY: 内存分配失败
 * 
 * 功能：分配内存并复制指定大小的数据
 */
enum pkcs11_rc serialargs_alloc_and_get(struct serialargs *args,
					void **out, size_t size);

/*
 * 检查是否还有剩余未读取的字节
 * 
 * @args: 序列化状态结构体
 * 
 * 返回值：
 * - true:  有剩余字节
 * - false: 所有数据已读取
 * 
 * 用途：验证参数完整性，检测无效的额外数据
 */
bool serialargs_remaining_bytes(struct serialargs *args);

/*
 * 提取会话句柄并转换为会话指针
 * 
 * @args:   序列化状态结构体
 * @client: 客户端结构（用于验证会话所有权）
 * @sess:   返回会话指针
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足
 * - PKCS11_CKR_SESSION_HANDLE_INVALID: 句柄无效或不属于该客户端
 * 
 * 功能：提取会话句柄并验证有效性和所有权
 */
enum pkcs11_rc serialargs_get_session_from_handle(struct serialargs *args,
						  struct pkcs11_client *client,
						  struct pkcs11_session **sess);

/*
 * 将数据序列化并追加到缓冲区（动态扩展）
 * 
 * @bstart: 缓冲区指针的地址（可能被realloc修改）
 * @blen:   当前缓冲区大小的地址（会被更新）
 * @data:   要追加的数据
 * @len:    数据大小
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 大小溢出
 * - PKCS11_CKR_DEVICE_MEMORY: 内存分配失败
 * 
 * 功能：扩展缓冲区并追加数据到末尾
 * 注意：调用者需释放 *bstart，成功时 *bstart 可能指向新地址
 */
enum pkcs11_rc serialize(char **bstart, size_t *blen, void *data, size_t len);

#endif /*PKCS11_TA_SERIALIZER_H*/
