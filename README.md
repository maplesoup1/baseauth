# SecureAuth.NetCore

这是一个基于ASP.NET Core 8.0的综合认证系统，支持多种认证方式，包括OAuth2、SAML SSO和传统用户名密码登录。

## 功能特性

### 🔐 多认证方式支持
- **OAuth2 提供商**: Google, Facebook, Microsoft
- **SAML SSO**: AWS SSO 集成
- **传统登录**: 用户名密码认证
- **JWT Token**: 安全的Token管理

### 🛡️ 安全特性
- JWT Token认证和授权
- 安全的Cookie配置（HttpOnly, Secure, SameSite）
- CORS跨域配置
- 安全头设置（XSS防护、内容类型嗅探防护等）
- IP地理位置追踪
- 设备信息记录

### 📊 用户管理
- 用户注册和登录
- 角色管理系统
- 登录历史记录
- 自动用户创建/更新（OAuth/SAML）

## 项目结构

```
SecureAuth.Api/
├── Controllers/          # API控制器
│   ├── AuthController.cs    # 认证相关API
│   └── SamlController.cs    # SAML SSO处理
├── Services/             # 业务服务层
│   ├── JwtService.cs        # JWT Token服务
│   ├── OAuthService.cs      # OAuth处理服务
│   └── SamlService.cs       # SAML处理服务
├── Models/               # 数据模型
│   ├── User.cs             # 用户实体
│   └── AuthModels.cs       # 认证相关DTOs
├── Data/                 # 数据访问层
│   └── ApplicationDbContext.cs
├── Middleware/           # 自定义中间件
│   └── JwtAuthenticationMiddleware.cs
├── Utils/                # 实用工具
│   └── DeviceUtil.cs
└── Program.cs            # 应用程序入口
```

## 快速开始

### 1. 环境要求
- .NET 8.0 SDK
- SQL Server（或修改为其他数据库）
- Redis（可选，用于缓存）

### 2. 配置环境变量

```bash
# JWT密钥（必须至少32个字符）
export JWT_SECRET="your-super-secret-jwt-key-here-must-be-at-least-32-characters"

# OAuth提供商配置
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export FACEBOOK_APP_ID="your-facebook-app-id"
export FACEBOOK_APP_SECRET="your-facebook-app-secret"
export MICROSOFT_CLIENT_ID="your-microsoft-client-id"
export MICROSOFT_CLIENT_SECRET="your-microsoft-client-secret"

# SAML配置
export AWS_SSO_SINGLE_SIGNON_URL="your-aws-sso-url"
```

### 3. 更新配置文件

修改 `appsettings.json` 中的数据库连接字符串和其他配置：

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "your-sql-server-connection-string"
  },
  "Authentication": {
    "Google": {
      "ClientId": "your-google-client-id",
      "ClientSecret": "your-google-client-secret"
    }
  }
}
```

### 4. 运行应用

```bash
cd SecureAuth.Api
dotnet restore
dotnet run
```

应用将在 `https://localhost:7001` 启动。

## API端点

### 认证端点

| 方法 | 端点 | 描述 |
|------|------|------|
| POST | `/api/auth/login` | 用户名密码登录 |
| POST | `/api/auth/register` | 用户注册 |
| GET | `/api/auth/user/check` | 获取当前用户信息 |
| POST | `/api/auth/logout` | 退出登录 |

### OAuth端点

| 方法 | 端点 | 描述 |
|------|------|------|
| GET | `/api/auth/oauth/google` | Google OAuth登录 |
| GET | `/api/auth/oauth/facebook` | Facebook OAuth登录 |
| GET | `/api/auth/oauth/microsoft` | Microsoft OAuth登录 |

### SAML端点

| 方法 | 端点 | 描述 |
|------|------|------|
| GET | `/saml2/sso` | 启动SAML SSO |
| POST | `/saml2/acs` | SAML断言消费服务 |
| GET/POST | `/saml2/sls` | SAML单点登出 |

## 使用示例

### 1. 传统登录

```bash
curl -X POST https://localhost:7001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "password": "password123"
  }'
```

### 2. OAuth登录流程

```javascript
// 前端重定向到OAuth提供商
window.location.href = 'https://localhost:7001/api/auth/oauth/google';

// 成功后会重定向回配置的前端URL，并设置JWT cookie
```

### 3. 获取用户信息

```bash
curl -X GET https://localhost:7001/api/auth/user/check \
  -H "Authorization: Bearer your-jwt-token"
```

## 开发配置

### 数据库迁移

系统使用Entity Framework Code First，首次运行时会自动创建数据库和表。

### 开发环境Cookie设置

在开发环境中，Cookie设置为：
- `HttpOnly: false` (便于调试)
- `Secure: false` (HTTP环境)
- 不设置Domain

### 生产环境安全配置

在生产环境中：
- 设置正确的JWT密钥
- 配置HTTPS
- 设置安全的Cookie选项
- 配置正确的CORS域名

## 前端集成

### JavaScript示例

```javascript
// 检查用户认证状态
async function checkAuth() {
  try {
    const response = await fetch('/api/auth/user/check', {
      credentials: 'include' // 包含cookies
    });
    
    if (response.ok) {
      const user = await response.json();
      console.log('当前用户:', user);
      return user;
    }
  } catch (error) {
    console.error('认证检查失败:', error);
  }
  return null;
}

// OAuth登录
function loginWithGoogle() {
  window.location.href = '/api/auth/oauth/google';
}

// 退出登录
async function logout() {
  await fetch('/api/auth/logout', {
    method: 'POST',
    credentials: 'include'
  });
  window.location.reload();
}
```

## 自定义和扩展

### 添加新的OAuth提供商

1. 在 `Program.cs` 中添加新的认证提供商配置
2. 在 `AuthController.cs` 中添加对应的端点
3. 更新 `OAuthService.cs` 中的用户信息提取逻辑

### 自定义角色和权限

修改 `Role` 模型和相关服务来实现自定义的角色权限系统。

### 添加Redis缓存

取消注释 `Program.cs` 中的Redis配置，并在服务中使用分布式缓存。

## 故障排除

### 常见问题

1. **JWT验证失败**: 检查JWT_SECRET环境变量设置
2. **OAuth回调失败**: 验证OAuth提供商的回调URL配置
3. **数据库连接失败**: 检查连接字符串和数据库服务状态
4. **CORS错误**: 确认前端域名在CORS配置中

### 日志查看

应用使用标准的ASP.NET Core日志记录，可以通过配置日志级别来获取详细信息：

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "SecureAuth.Api": "Debug"
    }
  }
}
```

## 安全注意事项

1. **绝对不要**在生产环境中使用默认的JWT密钥
2. 定期轮换JWT密钥
3. 设置适当的Token过期时间
4. 启用HTTPS
5. 配置适当的CORS策略
6. 定期更新依赖包

## 许可证

本项目基于原Java版本的认证系统移植，继承相同的许可证条款。