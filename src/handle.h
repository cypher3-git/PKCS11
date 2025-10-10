/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2020, Linaro Limited
 */

/*
 * ==============================================================================
 * 模块接口定义: 句柄管理数据库 (Handle Database)
 * ==============================================================================
 * 
 * 本头文件定义了句柄数据库的数据结构和操作接口。
 * 句柄数据库用于在PKCS#11 TA中安全地管理对象和会话的引用。
 * 
 * 【核心概念】
 * - 句柄(Handle): 客户端使用的32位无符号整数，用于引用TA内部对象
 * - 指针(Pointer): TA内部的实际对象内存地址
 * - 映射关系: 句柄值即为指针数组的索引
 * 
 * 【使用场景】
 * 1. 对象句柄管理（每个客户端独立的对象句柄空间）
 * 2. 会话句柄管理（全局会话句柄空间）
 * 
 * 【设计原则】
 * - 安全性: 客户端无法直接访问TA内存地址
 * - 高效性: O(1)查找复杂度，动态扩容均摊O(1)
 * - 灵活性: 支持句柄失效机制（对象销毁后防止访问）
 */

#ifndef PKCS11_TA_HANDLE_H
#define PKCS11_TA_HANDLE_H

#include <stddef.h>

/*
 * 句柄数据库结构体
 * 
 * 【字段说明】
 * @ptrs:     指针数组，存储句柄到指针的映射
 *            - 索引0保留为无效句柄，永不使用
 *            - 索引1~(max_ptrs-1)为有效句柄范围
 *            - NULL表示槽位空闲
 *            - INVALID_HANDLE_PTR表示槽位已失效
 * 
 * @max_ptrs: 指针数组的当前容量
 *            - 初始为0（延迟分配）
 *            - 按需扩容（初始4，然后倍增）
 * 
 * 【内存布局示例】
 * 容量为8的数据库：
 *   索引:  0      1      2      3      4      5      6      7
 *   内容: NULL  ptr1   ptr2   NULL  ptr4  INVAL  NULL  NULL
 *         ^^^^  ^^^^   ^^^^   ^^^^  ^^^^  ^^^^^  ^^^^  ^^^^
 *         保留  有效   有效   空闲  有效  失效   空闲  空闲
 * 
 * 【典型大小】
 * sizeof(struct handle_db) = 16 字节（64位系统）
 * - ptrs: 8字节指针
 * - max_ptrs: 4字节 + 4字节填充
 */
struct handle_db {
	void **ptrs;        /* 指针数组 */
	uint32_t max_ptrs;  /* 数组容量 */
};

/*
 * 初始化句柄数据库
 * 
 * @db: 指向待初始化的数据库结构
 * 
 * 功能：将数据库清零，延迟到首次使用时才分配内存
 * 
 * 调用要求：
 * - db 必须是有效指针（栈上或堆上分配）
 * - 对同一数据库重复调用是安全的
 */
void handle_db_init(struct handle_db *db);

/*
 * 销毁句柄数据库，释放内部数据结构
 * 
 * @db: 指向待销毁的数据库结构
 * 
 * 功能：
 * - 释放指针数组内存
 * - 重置数据库为初始状态
 * - 不释放db本身的内存
 * - 可以在destroy后再次init重新使用
 * 
 * 注意：
 * - 必须先释放所有指针指向的对象
 * - destroy只释放数组容器，不释放数组中的对象
 */
void handle_db_destroy(struct handle_db *db);

/*
 * 分配新句柄并建立映射
 * 
 * @db:  句柄数据库
 * @ptr: 要关联的对象指针（不能为NULL）
 * 
 * 返回值：
 * - 成功: 返回句柄值（>= 1）
 * - 失败: 返回 0（内存不足或参数无效）
 * 
 * 分配策略：
 * 1. 优先复用空闲槽位（NULL槽位）
 * 2. 无空闲槽位时扩容（倍增）
 * 3. 扩容失败返回0
 * 
 * 线程安全：单线程TA，无需加锁
 */
uint32_t handle_get(struct handle_db *db, void *ptr);

/*
 * 释放句柄并返回关联的指针
 * 
 * @db:     句柄数据库
 * @handle: 待释放的句柄
 * 
 * 返回值：
 * - 成功: 返回句柄原来关联的指针
 * - 失败: 返回 NULL（句柄无效）
 * 
 * 功能：
 * - 将槽位标记为空闲（设为NULL）
 * - 返回原指针，由调用者负责释放对象
 * - 释放后的槽位可被handle_get复用
 * 
 * 注意：调用者需自行释放返回的指针指向的对象
 */
void *handle_put(struct handle_db *db, uint32_t handle);

/*
 * 通过句柄查找关联的指针
 * 
 * @db:     句柄数据库
 * @handle: 句柄值
 * 
 * 返回值：
 * - 成功: 返回关联的对象指针
 * - 失败: 返回 NULL（句柄无效、已释放、或已失效）
 * 
 * 与handle_put的区别：
 * - lookup: 只读操作，不改变映射关系
 * - put:    读取并释放句柄
 * 
 * 失败原因：
 * - 句柄值为0或超出范围
 * - 槽位为NULL（已释放）
 * - 槽位为INVALID_HANDLE_PTR（已失效）
 */
void *handle_lookup(struct handle_db *db, uint32_t handle);

/*
 * 反向查找：根据指针查找对应的句柄
 * 
 * @db:  句柄数据库
 * @ptr: 对象指针
 * 
 * 返回值：
 * - 成功: 返回指针对应的句柄值（>= 1）
 * - 失败: 返回 0（指针未找到）
 * 
 * 性能：O(n)线性搜索，避免频繁调用
 * 
 * 用途：检查对象是否已分配句柄
 */
uint32_t handle_lookup_handle(struct handle_db *db, void *ptr);

/*
 * 将句柄标记为无效（但不释放槽位）
 * 
 * @db:     句柄数据库
 * @handle: 待标记为无效的句柄
 * 
 * 功能：
 * - 将槽位设为 INVALID_HANDLE_PTR
 * - 后续lookup会返回NULL
 * - 槽位不会被handle_get复用
 * 
 * 使用场景：
 * 对象被销毁但客户端可能仍持有句柄时，
 * 通过标记为无效防止访问已释放的内存
 * 
 * 错误处理：
 * 如果槽位为NULL（逻辑错误），触发TEE_Panic
 */
void handle_invalidate(struct handle_db *db, uint32_t handle);

#endif /*PKCS11_TA_HANDLE_H*/
