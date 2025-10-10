// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

/*
 * ==============================================================================
 * 模块名称: 序列化工具 (Serializer)
 * 文件功能: 提供REE与TEE之间数据序列化/反序列化的工具函数
 * ==============================================================================
 * 
 * 【模块职责】
 * 1. 从客户端传入的memref缓冲区中解析参数（反序列化）
 * 2. 将TA内部数据打包到memref缓冲区返回给客户端（序列化）
 * 3. 提供安全的边界检查，防止缓冲区溢出
 * 4. 支持动态分配内存并提取数据
 * 
 * 【核心概念】
 * - Memref: 客户端与TA之间共享的内存区域（GPD TEE API机制）
 * - 序列化: 将结构体/对象转换为连续的字节流
 * - 反序列化: 从字节流中解析出结构体/对象
 * 
 * 【数据流向】
 * 客户端 -> memref -> serialargs_get -> TA内部结构体
 * TA内部结构体 -> serialize -> memref -> 客户端
 * 
 * 【安全机制】
 * - 溢出检查: ADD_OVERFLOW宏检测整数溢出
 * - 边界检查: 确保读取不超出缓冲区范围
 * - 失败回滚: 内存分配失败时恢复读取位置
 * 
 * 【使用场景】
 * - 解析PKCS#11命令参数
 * - 提取对象属性模板
 * - 提取机制参数
 * - 返回查询结果
 */

#include <pkcs11_ta.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <trace.h>
#include <util.h>

#include "pkcs11_token.h"
#include "serializer.h"

/*
 * 初始化序列化参数解析器
 * 
 * @args: 序列化状态结构体
 * @in:   输入缓冲区起始地址（客户端传入的memref）
 * @size: 输入缓冲区总大小
 * 
 * 功能：
 * - 设置缓冲区起始位置和大小
 * - 初始化读取指针到缓冲区开头
 * - 准备后续的参数提取操作
 * 
 * 使用示例：
 *   struct serialargs args;
 *   serialargs_init(&args, params[0].memref.buffer, params[0].memref.size);
 *   serialargs_get_u32(&args, &slot_id);
 *   serialargs_get(&args, &flags, sizeof(flags));
 * 
 * 状态变化：
 * - start: 指向缓冲区开头（不变）
 * - next:  指向当前读取位置（初始化为开头）
 * - size:  缓冲区总大小（不变）
 */
void serialargs_init(struct serialargs *args, void *in, size_t size)
{
	args->start = in;  /* 缓冲区起始地址 */
	args->next = in;   /* 当前读取位置 */
	args->size = size; /* 缓冲区总大小 */
}

/*
 * 从序列化缓冲区中提取数据并复制到输出缓冲区
 * 
 * @args: 序列化状态结构体
 * @out:  输出缓冲区（由调用者分配，大小至少为size字节）
 * @size: 要提取的字节数
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足或溢出
 * 
 * 功能：
 * - 获取指向序列化数据的指针
 * - 将数据复制到调用者提供的输出缓冲区
 * - 自动推进读取位置
 * 
 * 与 serialargs_get_ptr 的区别：
 * - serialargs_get:     复制数据到输出缓冲区（安全，数据独立）
 * - serialargs_get_ptr: 返回指向原缓冲区的指针（高效，但数据共享）
 * 
 * 典型使用：
 *   uint32_t slot_id;
 *   rc = serialargs_get(&args, &slot_id, sizeof(slot_id));
 *   // slot_id 现在包含从客户端传来的值
 * 
 * 内存安全：
 * - 使用 TEE_MemMove（支持重叠区域）
 * - 边界检查由 serialargs_get_ptr 完成
 */
enum pkcs11_rc serialargs_get(struct serialargs *args, void *out, size_t size)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	void *src = NULL;

	/* 获取指向序列化数据的指针 */
	rc = serialargs_get_ptr(args, &src, size);
	if (!rc)
		TEE_MemMove(out, src, size);  /* 复制数据 */

	return rc;
}

/*
 * 内部辅助函数：分配内存并提取数据（支持前缀拼接）
 * 
 * @args:      序列化状态结构体
 * @orig_next: 原始读取位置（用于失败回滚）
 * @buf0:      前缀数据（如结构体头部）
 * @buf0_sz:   前缀数据大小
 * @out:       返回分配的内存指针
 * @size:      要从序列化缓冲区提取的数据大小
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 大小溢出
 * - PKCS11_CKR_DEVICE_MEMORY: 内存分配失败
 * 
 * 功能：
 * 1. 分配 buf0_sz + size 大小的内存
 * 2. 将 buf0 复制到新内存的开头
 * 3. 从序列化缓冲区提取 size 字节追加到后面
 * 4. 返回完整的内存块
 * 
 * 使用场景：
 * - 提取带头部的数据结构（如属性、对象）
 * - 例如：[属性头8字节][属性值N字节] 合并为一块内存
 * 
 * 失败处理：
 * - 内存分配失败时恢复读取位置（args->next = orig_next）
 * - 保证序列化状态的一致性
 * 
 * 内存管理：
 * - 分配的内存由调用者负责释放
 * - 使用 TEE_MALLOC_FILL_ZERO 清零内存
 */
static enum pkcs11_rc alloc_and_get(struct serialargs *args, char *orig_next,
				    const void *buf0, size_t buf0_sz,
				    void **out, size_t size)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint8_t *ptr = NULL;
	void *src = NULL;
	size_t sz = 0;

	/* 检查总大小是否溢出 */
	if (ADD_OVERFLOW(buf0_sz, size, &sz))
		return PKCS11_CKR_ARGUMENTS_BAD;

	/* 大小为0，返回NULL（合法场景） */
	if (!sz) {
		*out = NULL;
		return PKCS11_CKR_OK;
	}

	/* 获取指向序列化数据的指针 */
	rc = serialargs_get_ptr(args, &src, size);
	if (rc)
		return rc;

	/* 分配内存 */
	ptr = TEE_Malloc(sz, TEE_MALLOC_FILL_ZERO);
	if (!ptr) {
		args->next = orig_next;  /* 回滚读取位置 */
		return PKCS11_CKR_DEVICE_MEMORY;
	}

	/* 复制前缀数据（如结构体头） */
	TEE_MemMove(ptr, buf0, buf0_sz);
	/* 追加序列化数据 */
	TEE_MemMove(ptr + buf0_sz, src, size);

	*out = ptr;

	return PKCS11_CKR_OK;
}

/*
 * 分配内存并从序列化缓冲区提取数据
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
 * 功能：
 * - 分配 size 字节内存
 * - 从序列化缓冲区复制数据到新内存
 * - 推进读取位置
 * 
 * 与 serialargs_get 的区别：
 * - serialargs_get: 需要调用者预先分配输出缓冲区
 * - serialargs_alloc_and_get: 自动分配内存
 * 
 * 典型使用：
 *   void *data = NULL;
 *   rc = serialargs_alloc_and_get(&args, &data, data_size);
 *   if (!rc) {
 *       // 使用 data
 *       TEE_Free(data);  // 使用完毕后释放
 *   }
 */
enum pkcs11_rc serialargs_alloc_and_get(struct serialargs *args,
					void **out, size_t size)
{
	return alloc_and_get(args, args->next, NULL, 0, out, size);
}

/*
 * 获取指向序列化数据的指针（零拷贝）
 * 
 * @args: 序列化状态结构体
 * @out:  返回指向序列化缓冲区的指针
 * @size: 要访问的字节数
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足或地址溢出
 * 
 * 功能：
 * - 返回指向当前读取位置的指针
 * - 推进读取位置 size 字节
 * - 不复制数据（零拷贝，高效）
 * 
 * 安全检查：
 * 1. 检测地址溢出（next + size 是否溢出）
 * 2. 检测缓冲区越界（next + size 是否超出范围）
 * 
 * 注意事项：
 * - 返回的指针指向原始缓冲区，生命周期与缓冲区相同
 * - 不能修改指针指向的数据（客户端内存可能为只读）
 * - size为0时返回NULL（合法情况）
 * 
 * 典型使用：
 *   void *ptr = NULL;
 *   rc = serialargs_get_ptr(&args, &ptr, data_size);
 *   if (!rc)
 *       process_data(ptr, data_size);  // 直接使用，无需复制
 * 
 * 错误日志：
 * - 缓冲区不足时打印详细信息（总大小、剩余大小、请求大小）
 */
enum pkcs11_rc serialargs_get_ptr(struct serialargs *args, void **out,
				  size_t size)
{
	void *ptr = args->next;  /* 保存当前位置 */
	vaddr_t next_end = 0;

	/* 检测地址溢出：next + size 是否溢出虚拟地址空间 */
	if (ADD_OVERFLOW((vaddr_t)args->next, size, &next_end))
		return PKCS11_CKR_ARGUMENTS_BAD;

	/* size为0是合法的，返回NULL */
	if (!size) {
		*out = NULL;
		return PKCS11_CKR_OK;
	}

	/* 检查是否超出缓冲区范围 */
	if ((char *)next_end > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return PKCS11_CKR_ARGUMENTS_BAD;
	}

	/* 推进读取位置 */
	args->next += size;
	*out = ptr;

	return PKCS11_CKR_OK;
}

/*
 * 分配并提取单个属性（属性头+属性值）
 * 
 * @args: 序列化状态结构体
 * @out:  返回分配的属性结构指针
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足
 * - PKCS11_CKR_DEVICE_MEMORY: 内存分配失败
 * 
 * 序列化格式：
 * [struct pkcs11_attribute_head] + [属性值数据]
 * - id (4字节):   属性ID（如CKA_VALUE）
 * - size (4字节): 属性值大小
 * - data[]:       属性值（size字节）
 * 
 * 处理流程：
 * 1. 提取属性头（8字节）
 * 2. 根据head.size提取属性值
 * 3. 分配内存并合并为完整属性
 * 
 * 内存布局：
 * 返回的内存块包含：
 * - 开头: struct pkcs11_attribute_head
 * - 紧接着: 属性值数据
 * 
 * 使用示例：
 *   struct pkcs11_attribute_head *attr = NULL;
 *   rc = serialargs_alloc_get_one_attribute(&args, &attr);
 *   if (!rc) {
 *       // attr->id 是属性ID
 *       // attr->data 是属性值
 *       TEE_Free(attr);
 *   }
 */
enum pkcs11_rc
serialargs_alloc_get_one_attribute(struct serialargs *args,
				   struct pkcs11_attribute_head **out)
{
	struct pkcs11_attribute_head head = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	char *orig_next = args->next;
	void *p = NULL;

	/* 提取属性头 */
	rc = serialargs_get(args, &head, sizeof(head));
	if (rc)
		return rc;

	/* 分配内存并提取完整属性（头+值） */
	rc = alloc_and_get(args, orig_next, &head, sizeof(head), &p, head.size);
	if (rc)
		return rc;

	*out = p;

	return PKCS11_CKR_OK;
}

/*
 * 分配并提取对象属性列表（对象头+所有属性）
 * 
 * @args: 序列化状态结构体
 * @out:  返回分配的对象头结构指针
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足
 * - PKCS11_CKR_DEVICE_MEMORY: 内存分配失败
 * 
 * 序列化格式：
 * [struct pkcs11_object_head] + [序列化的属性数据]
 * - attrs_size (4字节):  attrs[]的总字节数
 * - attrs_count (4字节): 属性个数
 * - attrs[]:             连续存储的多个属性
 * 
 * 处理流程：
 * 1. 提取对象头（8字节）
 * 2. 根据attr.attrs_size提取所有属性数据
 * 3. 分配内存并合并为完整对象
 * 
 * 内存布局：
 * 返回的内存块包含：
 * - 开头: struct pkcs11_object_head
 * - 紧接着: 多个连续的属性（每个属性=头+值）
 * 
 * 使用示例：
 *   struct pkcs11_object_head *obj = NULL;
 *   rc = serialargs_alloc_get_attributes(&args, &obj);
 *   if (!rc) {
 *       // obj->attrs_count 是属性个数
 *       // obj->attrs 是所有属性的序列化数据
 *       TEE_Free(obj);
 *   }
 */
enum pkcs11_rc serialargs_alloc_get_attributes(struct serialargs *args,
					       struct pkcs11_object_head **out)
{
	struct pkcs11_object_head attr = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	char *orig_next = args->next;
	void *p = NULL;

	/* 提取对象头 */
	rc = serialargs_get(args, &attr, sizeof(attr));
	if (rc)
		return rc;

	/* 分配内存并提取完整对象（头+所有属性） */
	rc = alloc_and_get(args, orig_next, &attr, sizeof(attr), &p,
			   attr.attrs_size);
	if (rc)
		return rc;

	*out = p;

	return PKCS11_CKR_OK;
}

/*
 * 检查是否还有剩余未读取的字节
 * 
 * @args: 序列化状态结构体
 * 
 * 返回值：
 * - true:  还有剩余字节未读取
 * - false: 已读取完所有数据
 * 
 * 用途：
 * - 验证参数完整性（确保所有数据都被处理）
 * - 检测是否有额外的无效数据
 * 
 * 典型使用：
 *   if (serialargs_remaining_bytes(&args))
 *       return PKCS11_CKR_ARGUMENTS_BAD;  // 有多余数据
 */
bool serialargs_remaining_bytes(struct serialargs *args)
{
	return args->next < args->start + args->size;
}

/*
 * 从序列化缓冲区提取会话句柄并转换为会话指针
 * 
 * @args:   序列化状态结构体
 * @client: 客户端结构（用于验证会话所有权）
 * @sess:   返回会话指针
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 缓冲区不足
 * - PKCS11_CKR_SESSION_HANDLE_INVALID: 会话句柄无效或不属于该客户端
 * 
 * 功能：
 * 1. 从序列化缓冲区读取会话句柄（uint32_t）
 * 2. 通过句柄查找对应的会话结构
 * 3. 验证会话属于当前客户端
 * 
 * 安全性：
 * - 防止客户端A访问客户端B的会话
 * - 验证句柄有效性（存在且未销毁）
 * 
 * 典型使用：
 *   struct pkcs11_session *session = NULL;
 *   rc = serialargs_get_session_from_handle(&args, client, &session);
 *   if (rc)
 *       return rc;
 *   // 使用 session 进行后续操作
 */
enum pkcs11_rc serialargs_get_session_from_handle(struct serialargs *args,
						  struct pkcs11_client *client,
						  struct pkcs11_session **sess)
{
	uint32_t rv = PKCS11_CKR_GENERAL_ERROR;
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;

	/* 提取会话句柄 */
	rv = serialargs_get(args, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	/* 将句柄转换为会话指针（同时验证所有权） */
	session = pkcs11_handle2session(session_handle, client);
	if (!session)
		return PKCS11_CKR_SESSION_HANDLE_INVALID;

	*sess = session;

	return PKCS11_CKR_OK;
}

/*
 * 将数据序列化并追加到缓冲区（动态扩展）
 * 
 * @bstart: 缓冲区指针的地址（可能被realloc修改）
 * @blen:   当前缓冲区已用大小的地址（会被更新）
 * @data:   要追加的数据
 * @len:    数据大小
 * 
 * 返回值：
 * - PKCS11_CKR_OK: 成功
 * - PKCS11_CKR_ARGUMENTS_BAD: 大小溢出
 * - PKCS11_CKR_DEVICE_MEMORY: 内存分配失败
 * 
 * 功能：
 * 1. 扩展缓冲区大小（原大小 + len）
 * 2. 将数据复制到缓冲区末尾
 * 3. 更新缓冲区指针和大小
 * 
 * 内存管理：
 * - 使用 TEE_Realloc 扩展缓冲区
 * - 失败时原缓冲区保持不变
 * - 成功时 *bstart 可能指向新地址
 * 
 * 典型使用（构建返回数据）：
 *   char *buf = NULL;
 *   size_t size = 0;
 *   serialize(&buf, &size, &slot_id, sizeof(slot_id));
 *   serialize(&buf, &size, &flags, sizeof(flags));
 *   // buf 现在包含所有序列化的数据
 *   // 将 buf 复制到 output memref，然后 TEE_Free(buf)
 * 
 * 注意事项：
 * - 调用者需要在使用完毕后释放 *bstart
 * - 可以从NULL/0开始构建缓冲区
 */
enum pkcs11_rc serialize(char **bstart, size_t *blen, void *data, size_t len)
{
	char *buf = NULL;
	size_t nlen = 0;

	/* 检查新大小是否溢出 */
	if (ADD_OVERFLOW(*blen, len, &nlen))
		return PKCS11_CKR_ARGUMENTS_BAD;

	/* 扩展缓冲区 */
	buf = TEE_Realloc(*bstart, nlen);
	if (!buf)
		return PKCS11_CKR_DEVICE_MEMORY;

	/* 追加数据到缓冲区末尾 */
	TEE_MemMove(buf + *blen, data, len);

	/* 更新缓冲区指针和大小 */
	*blen = nlen;
	*bstart = buf;

	return PKCS11_CKR_OK;
}

