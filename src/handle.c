// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2020, Linaro Limited
 */

/*
 * ==============================================================================
 * 模块名称: 句柄管理数据库 (Handle Database)
 * 文件功能: 提供安全的句柄-指针映射机制，用于对象和会话的引用管理
 * ==============================================================================
 * 
 * 【模块职责】
 * 1. 维护句柄到内部指针的映射关系
 * 2. 防止客户端直接访问TA内部内存地址（安全隔离）
 * 3. 支持句柄的分配、查找、释放和失效操作
 * 4. 动态扩展句柄数组容量
 * 
 * 【核心数据结构】
 * struct handle_db {
 *     void **ptrs;        // 指针数组，索引即为句柄值
 *     uint32_t max_ptrs;  // 当前数组容量
 * };
 * 
 * 【句柄分配策略】
 * - 句柄值 0 保留为无效句柄
 * - 句柄值从 1 开始递增
 * - 初始容量为 4，不够时倍增扩容
 * - 优先复用已释放的句柄槽位
 * 
 * 【内存管理】
 * - 使用 TEE_Realloc 进行动态扩容
 * - 释放句柄时不缩减数组（避免频繁realloc）
 * - 销毁数据库时统一释放所有内存
 * 
 * 【安全机制】
 * - 无效句柄标记为 INVALID_HANDLE_PTR (~0)，区别于NULL和有效指针
 * - handle_lookup 会拒绝返回失效句柄对应的指针
 * - 句柄验证检查范围和有效性
 */

#include <stdlib.h>
#include <tee_internal_api.h>

#include "handle.h"

/*
 * 句柄数据库初始容量
 * 
 * 设计考虑：
 * - 设置为较小的2的幂（4）以节省内存
 * - 大多数数据库只使用少量句柄，初始4个足够
 * - 倍增扩容算法确保大数据库不会产生明显开销
 * - 例如：4 -> 8 -> 16 -> 32 -> 64 ...
 */
#define HANDLE_DB_INITIAL_MAX_PTRS	4

/*
 * 无效句柄指针标记值
 * 
 * 使用 ~0 (全1) 作为特殊标记，表示句柄已分配但被标记为无效
 * 
 * 三种状态：
 * - NULL (0x0):            句柄槽位空闲，可分配
 * - INVALID_HANDLE_PTR (~0): 句柄已失效，不可使用（对象已销毁但句柄未释放）
 * - 其他非零值:            有效句柄，指向实际对象
 * 
 * 使用场景：
 * 当对象被销毁但客户端仍持有句柄时，将指针设为 INVALID_HANDLE_PTR
 * 后续使用该句柄时会被拒绝，而不是访问野指针
 */
#define INVALID_HANDLE_PTR	((void *)~0)

/*
 * 初始化句柄数据库
 * 
 * @db: 指向待初始化的句柄数据库结构
 * 
 * 功能：
 * - 将数据库结构清零
 * - ptrs 初始化为 NULL（未分配内存）
 * - max_ptrs 初始化为 0（容量为0）
 * 
 * 内存管理：
 * - 不预先分配指针数组，延迟到首次使用时分配（节省内存）
 * 
 * 调用时机：
 * - 创建新客户端时初始化对象句柄数据库
 * - 打开会话时初始化会话相关数据库
 */
void handle_db_init(struct handle_db *db)
{
	TEE_MemFill(db, 0, sizeof(*db));
}

/*
 * 销毁句柄数据库，释放所有内存
 * 
 * @db: 指向待销毁的句柄数据库结构
 * 
 * 功能：
 * - 释放指针数组内存
 * - 重置数据库状态为初始值
 * 
 * 注意事项：
 * - 不会释放指针数组中指向的对象本身（调用者需要先释放对象）
 * - 仅释放指针数组这个容器
 * - db 本身的内存不会被释放（通常是栈上或嵌入在其他结构中）
 * 
 * 典型调用流程：
 * 1. 遍历所有有效句柄，释放对应的对象
 * 2. 调用 handle_db_destroy 释放句柄数据库本身
 * 3. 可以再次调用 handle_db_init 重新使用数据库
 */
void handle_db_destroy(struct handle_db *db)
{
	if (db) {
		TEE_Free(db->ptrs);    /* 释放指针数组 */
		db->ptrs = NULL;       /* 防止悬空指针 */
		db->max_ptrs = 0;      /* 重置容量 */
	}
}

/*
 * 分配新句柄，建立句柄到指针的映射
 * 
 * @db:  句柄数据库
 * @ptr: 要关联的对象指针（不能为NULL或INVALID_HANDLE_PTR）
 * 
 * 返回值：
 * - 成功: 返回句柄值（>= 1）
 * - 失败: 返回 0（表示无效句柄）
 * 
 * 算法流程：
 * 1. 参数验证（拒绝NULL、INVALID_HANDLE_PTR）
 * 2. 尝试复用空闲槽位（从索引1开始查找NULL槽位）
 * 3. 如果没有空闲槽位，扩容指针数组
 *    - 首次分配: 容量设为 HANDLE_DB_INITIAL_MAX_PTRS (4)
 *    - 后续扩容: 容量翻倍 (4->8->16->32->64...)
 * 4. 将指针存入找到的槽位，返回索引作为句柄
 * 
 * 内存管理：
 * - 使用 TEE_Realloc 扩容，失败时返回0（原数组不变）
 * - 新扩容的区域清零，确保为NULL（表示空闲）
 * - 扩容时间复杂度：O(1)均摊（倍增策略）
 * 
 * 句柄分配规则：
 * - 索引 0 保留为无效句柄，永不分配
 * - 有效句柄范围: [1, max_ptrs-1]
 * - 优先复用已释放的槽位（提高内存利用率）
 * 
 * 示例：
 *   初始: max_ptrs=0, ptrs=NULL
 *   第1次: 扩容到4, 分配句柄1 -> [NULL, ptr1, NULL, NULL]
 *   第2次: 复用槽位, 分配句柄2 -> [NULL, ptr1, ptr2, NULL]
 *   第5次: 扩容到8, 分配句柄5 -> [NULL, ptr1, ptr2, ptr3, ptr4, ptr5, NULL, NULL]
 */
uint32_t handle_get(struct handle_db *db, void *ptr)
{
	uint32_t n = 0;
	void *p = NULL;
	uint32_t new_max_ptrs = 0;

	/* 参数验证：拒绝非法指针 */
	if (!db || !ptr || ptr == INVALID_HANDLE_PTR)
		return 0;

	/* 
	 * 步骤1: 尝试查找空闲槽位（从索引1开始，0保留为无效句柄）
	 * 时间复杂度: O(n)，但通常数据库很小
	 */
	for (n = 1; n < db->max_ptrs; n++) {
		if (!db->ptrs[n]) {
			db->ptrs[n] = ptr;  /* 找到空闲槽位，直接使用 */
			return n;
		}
	}

	/*
	 * 步骤2: 没有空闲槽位，需要扩容
	 * 扩容策略：
	 * - 若当前为空（首次使用），分配初始容量4
	 * - 若已有容量，翻倍扩容
	 */
	if (db->max_ptrs)
		new_max_ptrs = db->max_ptrs * 2;  /* 倍增扩容 */
	else
		new_max_ptrs = HANDLE_DB_INITIAL_MAX_PTRS;  /* 首次分配 */

	/* 执行扩容操作 */
	p = TEE_Realloc(db->ptrs, new_max_ptrs * sizeof(void *));
	if (!p)
		return 0;  /* 内存不足，扩容失败 */
	
	db->ptrs = p;  /* 更新指针（realloc可能改变地址） */
	
	/* 将新扩容的区域清零（标记为空闲） */
	TEE_MemFill(db->ptrs + db->max_ptrs, 0,
		    (new_max_ptrs - db->max_ptrs) * sizeof(void *));
	db->max_ptrs = new_max_ptrs;  /* 更新容量 */

	/*
	 * 步骤3: 使用新扩容出的第一个槽位
	 * 此时 n == 旧的max_ptrs，正好是新区域的第一个位置
	 */
	db->ptrs[n] = ptr;
	return n;
}

/*
 * 内部辅助函数：验证句柄是否在有效范围内
 * 
 * @db:     句柄数据库
 * @handle: 待验证的句柄值
 * 
 * 返回值：
 * - true:  句柄值在有效范围内
 * - false: 句柄无效（为0、超出范围、数据库为NULL）
 * 
 * 验证规则：
 * 1. 数据库指针不为NULL
 * 2. 句柄值不为0（0保留为无效句柄）
 * 3. 句柄值在数组容量范围内（< max_ptrs）
 * 
 * 注意：
 * - 这只是范围检查，不检查槽位是否真正被使用
 * - 即使槽位为NULL或INVALID_HANDLE_PTR，只要索引合法就返回true
 */
static bool handle_is_valid(struct handle_db *db, uint32_t handle)
{
	return db && handle && handle < db->max_ptrs;
}

/*
 * 释放句柄，解除句柄与指针的映射关系
 * 
 * @db:     句柄数据库
 * @handle: 待释放的句柄值
 * 
 * 返回值：
 * - 成功: 返回句柄原来关联的指针
 * - 失败: 返回 NULL（句柄无效或已释放）
 * 
 * 功能：
 * - 将句柄对应的槽位设为NULL（标记为空闲）
 * - 返回原指针，由调用者负责释放对象内存
 * - 释放后的槽位可被后续的 handle_get 复用
 * 
 * 使用场景：
 * - 销毁对象时释放其句柄
 * - 关闭会话时释放会话句柄
 * 
 * 注意事项：
 * - 不会释放指针指向的对象内存（调用者需自行释放）
 * - 释放后句柄值变为无效，后续查找会返回NULL
 * - 可能返回INVALID_HANDLE_PTR，表示句柄已失效
 * 
 * 典型调用流程：
 *   void *obj = handle_put(db, handle);  // 解除映射
 *   if (obj && obj != INVALID_HANDLE_PTR)
 *       destroy_object(obj);              // 释放对象
 */
void *handle_put(struct handle_db *db, uint32_t handle)
{
	void *p = NULL;

	/* 验证句柄有效性 */
	if (!handle_is_valid(db, handle))
		return NULL;

	p = db->ptrs[handle];       /* 保存原指针 */
	db->ptrs[handle] = NULL;    /* 释放槽位 */
	return p;                   /* 返回原指针给调用者 */
}

/*
 * 通过句柄查找关联的指针
 * 
 * @db:     句柄数据库
 * @handle: 句柄值
 * 
 * 返回值：
 * - 成功: 返回句柄关联的对象指针
 * - 失败: 返回 NULL（句柄无效、已释放、或已失效）
 * 
 * 与 handle_put 的区别：
 * - handle_lookup: 仅查询，不改变映射关系
 * - handle_put:    查询并释放句柄
 * 
 * 失败情况：
 * 1. 句柄值为0（无效句柄）
 * 2. 句柄值超出范围
 * 3. 槽位为NULL（句柄已释放）
 * 4. 槽位为INVALID_HANDLE_PTR（对象已销毁但句柄未释放）
 * 
 * 典型使用：
 *   struct pkcs11_object *obj = handle_lookup(db, client_handle);
 *   if (!obj)
 *       return PKCS11_CKR_OBJECT_HANDLE_INVALID;
 *   // 使用 obj ...
 */
void *handle_lookup(struct handle_db *db, uint32_t handle)
{
	/* 验证句柄有效性和状态 */
	if (!handle_is_valid(db, handle) ||
	    db->ptrs[handle] == INVALID_HANDLE_PTR)
		return NULL;

	return db->ptrs[handle];
}

/*
 * 将句柄标记为无效，但不释放槽位
 * 
 * @db:     句柄数据库
 * @handle: 待标记为无效的句柄
 * 
 * 功能：
 * - 将槽位设为 INVALID_HANDLE_PTR（区别于NULL和有效指针）
 * - 后续 handle_lookup 会拒绝返回该槽位的值
 * - 槽位不会被 handle_get 复用（除非先调用 handle_put）
 * 
 * 使用场景：
 * - 对象被销毁，但客户端仍可能持有句柄引用
 * - 通过标记为无效防止访问已释放的内存（安全防护）
 * 
 * 与 handle_put 的区别：
 * - handle_invalidate: 标记为无效但不释放槽位
 * - handle_put:        释放槽位供后续复用
 * 
 * 错误处理：
 * - 如果槽位已经为NULL（表示逻辑错误），触发 TEE_Panic
 * - 这表示试图标记一个未分配的句柄为无效
 * 
 * 典型调用流程：
 * 1. 销毁对象
 * 2. 调用 handle_invalidate 标记所有指向该对象的句柄
 * 3. 后续客户端使用这些句柄会收到错误
 */
void handle_invalidate(struct handle_db *db, uint32_t handle)
{
	if (handle_is_valid(db, handle)) {
		/* 检测逻辑错误：试图失效一个未分配的句柄 */
		if (!db->ptrs[handle])
			TEE_Panic(TEE_ERROR_GENERIC);

		/* 标记为无效状态 */
		db->ptrs[handle] = INVALID_HANDLE_PTR;
	}
}

/*
 * 反向查找：根据指针查找对应的句柄值
 * 
 * @db:  句柄数据库
 * @ptr: 对象指针
 * 
 * 返回值：
 * - 成功: 返回指针对应的句柄值（>= 1）
 * - 失败: 返回 0（指针未找到或为NULL/INVALID_HANDLE_PTR）
 * 
 * 算法：
 * - 线性搜索整个指针数组
 * - 时间复杂度: O(n)
 * 
 * 使用场景：
 * - 确定某个对象是否已被分配句柄
 * - 获取对象的句柄值（用于返回给客户端）
 * 
 * 注意事项：
 * - 效率较低（O(n)），应避免频繁调用
 * - 不会匹配INVALID_HANDLE_PTR
 * - 如果同一指针被多次注册（不应发生），返回第一个匹配的句柄
 * 
 * 典型使用：
 *   uint32_t handle = handle_lookup_handle(db, obj);
 *   if (!handle)
 *       handle = handle_get(db, obj);  // 未分配则分配新句柄
 */
uint32_t handle_lookup_handle(struct handle_db *db, void *ptr)
{
	uint32_t n = 0;

	/* 忽略NULL和无效指针 */
	if (ptr && ptr != INVALID_HANDLE_PTR) {
		/* 从索引1开始遍历（0保留） */
		for (n = 1; n < db->max_ptrs; n++)
			if (db->ptrs[n] == ptr)
				return n;  /* 找到匹配的指针 */
	}

	return 0;  /* 未找到 */
}
