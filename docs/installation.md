# 安装与正式发行

完整部署使用 [README 的一键入口](../README.md#linux-一键安装与部署)。本页说明版本选择、工具安装及发行验证，供高级运维和自动化使用。

## 版本与信任

无操作参数时，脚本解析一次最新稳定版并冻结本次版本，自动准备固定摘要的官方 cosign 3.1.3。验证 SHA256SUMS 的 Sigstore bundle，绑定 GitHub OIDC issuer 和本仓库 release.yml 的精确标签身份，再检查归档摘要、ELF 架构、程序版本及旧配置兼容性。

资产缺失、版本过旧或验证失败即停止，不回退到未签名资产、源码编译或手动上传。不提供跳过验签参数。新程序原子安装，原程序按摘要保存在 `/usr/local/lib/nodectl/versions/`；未恢复事务会阻止替换。

在已下载的同一脚本后添加 `--version v0.6.4` 可固定版本；`--token-file /root/cf-token` 把受保护凭据文件交给 Rust 向导，不把 Token 真值放入 argv。

## 只安装或升级 nodectl

此模式不调用部署、不操作服务，适合已有自动化链路：

```sh
sh node-config-manager-setup.sh --install-only --version v0.6.4 --dry-run
sudo sh node-config-manager-setup.sh --install-only --version v0.6.4 --execute
```

原有明确指定 `--execute/--dry-run` 的命令保留工具安装语义。`nodectl upgrade` 也调用工具安装模式，避免递归进入向导。固定版本的 dry-run 不下载或创建文件；未固定版本时只会查询最新版本元数据。

完整向导需要终端。无终端时不会隐式执行，使用工具安装模式及现有 `nodectl deploy --non-interactive` 的预览和 `--approve` 接口。

## 网络与离线资产

默认直接使用 GitHub HTTPS，支持标准 `http_proxy/https_proxy/ALL_PROXY/NO_PROXY` 及自定义 CA 环境变量；不会自动选用第三方镜像，也不输出含认证信息的代理值。

`--bundle-dir /root/offline --version v0.6.4` 从本地目录读取对应架构归档、SHA256SUMS 和 Sigstore bundle；仍然验签。需在 PATH 或该目录提供固定摘要的官方 `cosign-linux-amd64` / `cosign-linux-arm64`。该选项仅让程序资产离线；系统软件、DNS、CA 和 WARP 的网络需求仍需另行满足，不能宣称整套部署离线。

## 发布与源码

两个架构均以 Debian 12 glibc 基线原生构建。归档包括程序、许可、依赖许可、CycloneDX SBOM 和构建信息；Release 包含清单、Sigstore bundle、安装器及发行说明。可额外使用 `gh attestation verify <archive> --repo reina0721/node-config-manager` 检查构建证明。

正式版本来自 [GitHub Releases](https://github.com/reina0721/node-config-manager/releases)。源码开发构建见 [贡献指南](../CONTRIBUTING.md)，本地候选不能冒充正式发行资产。系统矩阵与交付证据见 [验收记录](defect/08-one-command-delivery.md)。

全量质量及系统集成工作流只在手动触发时运行；标签触发的 Release 工作流仅原生构建、检查实际归档、生成 SBOM、签名及验证上传来源证明。不会为打包安装节点运行依赖；生产服务仍在目标主机原生运行。

## 网页在线切换版本

从发布了该功能的 v0.7.0 起，打开 **运维中心 → nodectl 版本管理**，选择或输入正式版标签。高于当前版本时升级，相同版本时重新安装，低于当前版本时回退。切换会下载签名归档、校验目标版本能读取当前及上一节点快照，然后一起激活程序、API 与静态后台。API 会短暂重启，完成后刷新网页并使用原管理员 Token 登录。后台展示最后一次切换状态，服务端日志可通过 `journalctl -u nodectl-admin-version-switch` 查看。

网页切换的最低目标为 v0.6.5。启用浏览器认证时，最低目标为 v0.7.1，程序版本变更时会重新加载认证服务。v0.6.5 的发布程序只能读取它支持的节点快照。目标不兼容时，切换在替换程序前停止。仓库改名前 v0.6.1–v0.6.5 的归档从当前仓库下载，验签固定使用各版本发行时的工作流身份。

从 v0.6.5 首次升级到具备网页切换的版本，或回退到 v0.6.5 后再次升级，需要先通过 SSH 安装新版控制台。正式资产发布后，用新版 `install.sh` 执行，端口填写已有后台的 HTTPS 端口。

```sh
sudo sh node-config-manager-setup.sh --switch-admin --version v0.7.1 --admin-port 9443 --execute
```
