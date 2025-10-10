/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_SANITIZE_OBJECT_H
#define PKCS11_TA_SANITIZE_OBJECT_H

#include "serializer.h"

/*
 * sanitize_consistent_class_and_type - 检查对象类型是否匹配对象类别
 *
 * @attrs - 对象属性
 * 如果类别/类型匹配则返回 true，否则返回 false
 */
bool sanitize_consistent_class_and_type(struct obj_attrs *attrs);

/**
 * sanitize_client_object - 从序列化对象设置序列化器
 *
 * @dst - 跟踪生成的序列化对象的输出结构
 * @head - 指向格式化的序列化对象的指针（其头部）
 * @size - 序列化二进制 blob 的字节大小
 * @class_hint - 如果序列化对象中不存在，则添加到模板的类别提示
 * @type_hint - 如果序列化对象中不存在，则添加到模板的类型提示
 *
 * 此函数将属性列表从客户端 API 属性头部复制到 PKCS11 TA 内部属性结构中。
 * 它生成一个格式一致且属性 ID 已识别的序列化属性列表。
 *
 * @head 指向以 pkcs11 属性头部开始的 blob。
 * @head 可能指向未对齐的地址。
 * 此函数分配、填充并将序列化属性列表返回到序列化器容器中。
 */
enum pkcs11_rc sanitize_client_object(struct obj_attrs **dst, void *head,
				      size_t size, uint32_t class_hint,
				      uint32_t type_hint);

/* 调试：将属性内容转储为调试跟踪 */
void trace_attributes_from_api_head(const char *prefix, void *ref, size_t size);

#endif /*PKCS11_TA_SANITIZE_OBJECT_H*/
