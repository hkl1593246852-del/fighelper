# fighelper

iOS 26.5 / 27.0 / 27.0.1 上的 CoreMedia bytestream XPC 帮手。把 `Documents/queue.txt`
里的每一条 `tag<TAB>path` 送进 `com.apple.coremedia.mediaplaybackd.bytestream.xpc`，
拿回守护进程 dup 出来的 fd：目录走 `fdopendir`/`readdir`，文件走 `fstat`+`pread` 全量落盘。

- 读 + 列目录：本 App（CVE-2026-112706 形态）
- 写：主机侧 AirLift（本仓库不涉及）

## 一、CI 出包

仓库自带 `.github/workflows/build.yml`：`macos-15` 上装 XcodeGen 生成工程、
`xcodebuild` 无签名 archive、打包成未签名 IPA，产物在 Actions 的
`fighelper-ipa` artifact 里（含 `sha256.txt`）。

```bash
git init
git add .
git commit -m "fighelper"
git branch -M main
git remote add origin git@github.com:<你>/fighelper.git
git push -u origin main
```

Actions 里跑完后，下载 `fighelper-unsigned.ipa`。

## 二、签名安装（Windows / macOS 均可）

```powershell
sideloadly.exe -u <UDID> -a you@example.com -p <app-specific-password> fighelper-unsigned.ipa
```

首次启动后到 `设置 → 隐私与安全性 → 开发者模式` 打开并重启，再信任证书。
`Info.plist` 带了 `UIFileSharingEnabled`，所以 `Documents/` 在「文件」App 里直接可见。

## 三、跑

```bash
# 推队列（每行 tag<TAB>绝对路径；第三列可选，换服务名）
python3 iostool.py ls /private/var/mobile/Media/iTunes_Control/iTunes
```

手工等价操作：

```bash
pymobiledevice3 apps afc com.you.fighelper push queue.txt /Documents/queue.txt
pymobiledevice3 apps launch com.you.fighelper
pymobiledevice3 apps afc com.you.fighelper pull /Documents/DONE ./DONE
pymobiledevice3 apps afc com.you.fighelper pull /Documents/out/index.txt ./index.txt
pymobiledevice3 apps afc com.you.fighelper pull /Documents/fig.log ./fig.log
```

## 四、产物

`Documents/out/` 下：

| 文件 | 内容 |
|---|---|
| `<tag>.dir` | 目录成员，按名字排序，一行一个 |
| `<tag>.bin` | 文件内容（≤ 8 MB） |
| `<tag>.meta` | `size` / `uid` / `mode` / 头 64 字节 hex |
| `index.txt` | 本次产生的全部文件名 |

`Documents/fig.log` 是同一条日志，另有 `DONE` 标记（主机侧轮询它判断完成）。

## 五、判读

| 日志 | 含义 |
|---|---|
| `STEP2 connected to ...` | 服务可连，无需 entitlement |
| `STEP3 '.rp1' reply=dictionary`、`'.org' completeSt=0 origin=true` | 握手成功 |
| `STREAM[tag] oid=... len=...` | 守护进程已打开该路径并给出 fd |
| `DIR[tag] entries=N` | 真 readdir 成功 |
| `DENIED[tag] err=-12203` | 路径存在但服务端拒绝 |
| `DENIED[tag] err=-17913` | 路径不存在 |
| `CTRL` 行 | 自检对照：App 自己 `open()` 同一路径应得 EPERM，而 fd 能读 |

## 六、能力边界

| 项 | 范围 |
|---|---|
| 可读域 | 实测只有 `/private/var/mobile/Media/iTunes_Control/iTunes/`；其余路径给存在性判读 |
| 写 | 本链路服务端拒绝；写走 AirLift |
| 内核 / root | 无 |

## 七、结构

```
project.yml                 XcodeGen 工程描述（纯文本，可离线编辑）
src/Info.plist              App 描述（含文件共享）
src/main.m                  UIApplicationMain
src/AppDelegate.{h,m}       最小窗口 + 后台跑 figRun()
src/Fig.{h,m}               符号解析、握手、Curl、fd、readdir/pread
.github/workflows/build.yml  macOS runner 出未签名 IPA
```
