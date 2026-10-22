# 贡献指南

## 这个仓库和上游的关系

本项目是 [QiuChenly/ida-pro-mcp-enhancement](https://github.com/QiuChenly/ida-pro-mcp-enhancement)
的可安装发行版，后者又基于 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)。

改动分两类，处理方式不同：

| 类型 | 说明 | 建议去向 |
| --- | --- | --- |
| 通用 bug 修复 | 与具体部署无关 | 优先提给上游 mrexodia/QiuChenly |
| 部署/打包相关 | launcher、installer、wheel 打包 | 提到本仓库 |

## 开发环境

```bash
git clone https://github.com/Sumcam-L/ida-pro-mcp-enhanced
cd ida-pro-mcp-enhanced
uv venv && uv pip install -e .
```

改完 Python 代码后，如果用的是 `pip install -e .`，除了插件目录那份副本
需要重新同步（IDA 加载的是插件目录里的文件，不是 site-packages 里的）：

```bash
ida-mcp-setup
```

然后在 IDA 里按 **Ctrl+Alt+M** 重连，让插件重新 import。

> 注意：`ida_mcp.py` 在重连时会同时卸载 `ida_mcp` 和 `broker` 两个包，
> 所以 `broker/*.py` 的改动也会生效。这个行为是本地补丁之一，别改回去。

## 测试

```bash
python -m pytest tests/ -q
```

仓库里有几处需要真实 IDB 的路径（`idasync` 相关）无法在 CI 里跑，
会在没有 IDA 时自动跳过。

改 `sync.py` 时请特别小心：超时机制有两版致命实现被删掉了（详见 `PATCHES.md`），
**不要**改回 `sys.setprofile` 抛异常或 `PyThreadState_SetAsyncExc` 的方案——
两者都会把 IDA 主线程锁死。

## 提交 PR

1. 大改动请先开 issue 讨论
2. 一个 PR 只做一件事
3. 涉及行为变更的，同步更新 `PATCHES.md`

## 许可证

提交即表示同意以 MIT 许可证发布你的贡献。同时请保留 `NOTICE` 中的上游署名。
