# war-audit

扫描浏览器扩展 `manifest.json`，检测 `web_accessible_resources` 和 `externally_connectable` 的安全暴露风险。

## 为什么要做这个

浏览器扩展的 `web_accessible_resources`（WAR）会把扩展内部文件暴露给网页。当它配合宽泛的匹配模式（`<all_urls>`）或敏感资源类型（JS/HTML/JSON/WASM）时，会形成一个攻击面：任意网页可以读取扩展内部资产，一旦这些资产引用了特权 API，就可能把 XSS 链式升级为扩展权限提权。

`externally_connectable` 则允许网页向扩展发消息，若 `onMessageExternal` 处理器未校验来源，任意页面都能触发它的特权行为。

这两个是 Chrome 官方文档明确警告的扩展攻击面，但市面上几乎没有专门检测它们的轻量工具。

## 安装

```bash
npm install -g war-audit
# 或直接用 npx
npx war-audit <manifest.json>
```

## 用法

```bash
# 直接扫一个 manifest.json
war-audit path/to/manifest.json

# 或扫整个扩展目录（自动找 manifest.json）
war-audit path/to/extension/
```

退出码：`0` 表示未发现高危风险，`1` 表示发现 high 级风险（可用于 CI 门禁）。

## 检测项

| 类型 | 风险 | 说明 |
|---|---|---|
| `broad-exposure` | high | WAR 通过 `<all_urls>` / `*://*/*` 等暴露给所有网站 |
| `sensitive-resource` | high | JS/HTML/JSON/WASM 等敏感资源被做成 web-accessible |
| `broad-connectable` | medium | `externally_connectable` 对任意来源开放 |

兼容 MV2（`string[]`）和 MV3（`object[]`）两种 WAR 格式。

## 示例

对这样的 manifest：

```json
{
  "manifest_version": 3,
  "web_accessible_resources": [
    { "resources": ["injected.js"], "matches": ["<all_urls>"] }
  ]
}
```

输出：

```
Found 2 finding(s):

[HIGH] broad-exposure
  Web-accessible resources are exposed to all websites via '<all_urls>'...

[HIGH] sensitive-resource
  Sensitive resource types ('injected.js') are web-accessible...
```

## 开发

```bash
npm install
npm run build    # 编译到 dist/
npm test         # 跑测试
```

## License

MIT
