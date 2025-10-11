# PKCS#11 Trusted Application (TA) 实现

## 项目简介

这是一个基于 OP-TEE 的 PKCS#11 可信应用（Trusted Application）实现，提供了完整的密码学操作接口。本项目包含中文注释，便于理解和学习。

## 功能特性

### 核心功能模块

1. **令牌管理**
   - 插槽和令牌信息查询
   - 机制能力查询
   - 会话管理

2. **密钥管理**
   - 对称密钥生成（AES等）
   - 非对称密钥对生成（RSA/ECC）
   - 密钥销毁和属性管理
   - 随机数生成

3. **加密解密**
   - 支持 AES（ECB, CBC, CTR, GCM等模式）
   - 支持 RSA 加密
   - 一次性操作和流式操作

4. **签名验签**
   - RSA 签名（PKCS#1, PSS）
   - ECDSA 签名
   - EdDSA 签名
   - 支持多种哈希算法

5. **摘要计算**
   - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
   - MD5
   - HMAC 操作

6. **高级功能**
   - 密钥派生
   - 密钥包装/解包
   - 对象查找和属性操作

## 目录结构

```
.
├── include/
│   └── pkcs11_ta.h          # PKCS#11 TA 头文件定义
├── src/
│   ├── entry.c              # TA 入口点和命令分发
│   ├── pkcs11_token.c       # 令牌管理
│   ├── object.c             # 对象管理
│   ├── processing.c         # 密码学操作主控制
│   ├── processing_aes.c     # AES 算法实现
│   ├── processing_rsa.c     # RSA 算法实现
│   ├── processing_ec.c      # ECC 算法实现
│   ├── processing_digest.c  # 摘要算法实现
│   ├── attributes.c         # 属性处理
│   ├── serializer.c         # 序列化/反序列化
│   └── ...
├── scripts/
│   └── ...                  # 辅助脚本
└── README.md                # 本文件
```

## PKCS#11 命令支持

本实现支持 52 种 PKCS#11 命令，涵盖：

- **基础设施**：PING, SLOT_LIST, TOKEN_INFO, SESSION 管理
- **身份认证**：LOGIN, LOGOUT, PIN 管理
- **对象操作**：CREATE, DESTROY, FIND, GET/SET 属性
- **加密解密**：ENCRYPT/DECRYPT (INIT/UPDATE/FINAL/ONESHOT)
- **签名验签**：SIGN/VERIFY (INIT/UPDATE/FINAL/ONESHOT)
- **摘要计算**：DIGEST (INIT/UPDATE/FINAL/ONESHOT)
- **密钥生成**：GENERATE_KEY, GENERATE_KEY_PAIR
- **密钥操作**：DERIVE_KEY, WRAP_KEY, UNWRAP_KEY
- **随机数**：GENERATE_RANDOM, SEED_RANDOM

## 技术规范

- **标准**：PKCS#11 v2.40
- **平台**：OP-TEE (Open Portable Trusted Execution Environment)
- **接口**：GlobalPlatform TEE Internal Core API
- **语言**：C

## 编译说明

本 TA 是 OP-TEE 项目的一部分，需要在 OP-TEE 构建环境中编译：

```bash
# 在 OP-TEE 构建系统中
make -C optee_os \
    CFG_PKCS11_TA=y \
    PLATFORM=<your_platform>
```

## 使用示例

客户端应用通过 PKCS#11 标准 API 与 TA 通信：

```c
CK_RV rv;
CK_SESSION_HANDLE session;

// 初始化库
rv = C_Initialize(NULL);

// 打开会话
rv = C_OpenSession(slot_id, flags, NULL, NULL, &session);

// 执行加密操作
rv = C_EncryptInit(session, &mechanism, key);
rv = C_Encrypt(session, plaintext, plaintext_len, ciphertext, &ciphertext_len);

// 关闭会话
rv = C_CloseSession(session);
```

## 精简版方案

如果不需要完整的 PKCS#11 功能，可以参考以下精简方案：

### 方案 A：最小核心版（15 个命令）
适用于基本的密钥管理和加解密需求：
- PING, SLOT_LIST, TOKEN_INFO, OPEN_SESSION, CLOSE_SESSION
- GENERATE_KEY, GENERATE_KEY_PAIR, DESTROY_OBJECT, GENERATE_RANDOM
- ENCRYPT_ONESHOT, DECRYPT_ONESHOT
- SIGN_ONESHOT, VERIFY_ONESHOT
- DIGEST_ONESHOT
- GET_ATTRIBUTE_VALUE

###方案 B：标准精简版（21 个命令）
适用场景： 常规商业应用，包含完整的密钥管理和常用操作
= 方案 A (15个)
+ SESSION_INFO
+ LOGIN, LOGOUT
+ FIND_OBJECTS_INIT, FIND_OBJECTS, FIND_OBJECTS_FINAL

###方案 C：增强精简版（27-30 个命令）
适用场景： 需要流式处理大数据的应用
= 方案 B (21个)
+ ENCRYPT_INIT, ENCRYPT_UPDATE, ENCRYPT_FINAL
+ DECRYPT_INIT, DECRYPT_UPDATE, DECRYPT_FINAL
或
+ SIGN_INIT, SIGN_UPDATE, SIGN_FINAL
+ VERIFY_INIT, VERIFY_UPDATE, VERIFY_FINAL

## 贡献指南

欢迎提交 Issue 和 Pull Request！

## 许可证

BSD-2-Clause

## 参考资源

- [PKCS#11 规范](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [OP-TEE 文档](https://optee.readthedocs.io/)
- [GlobalPlatform TEE API](https://globalplatform.org/specs-library/tee-internal-core-api-specification/)

## 联系方式

- GitHub: [@cypher3-git](https://github.com/cypher3-git)
- 项目地址: [https://github.com/cypher3-git/PKCS11](https://github.com/cypher3-git/PKCS11)

---

**注意**：本项目包含完整的中文注释，便于中文开发者学习和理解 PKCS#11 TA 的实现细节。

