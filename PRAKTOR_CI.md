# Praktor CI

仓库内的 `Praktor` workflow 入口为：

- `praktor_p2p_ci.yml`
- `praktor_p2p_smoke_ci.yml`
- `run_praktor_p2p.ps1`
- `run_praktor_p2p_tmux.sh`
- `run_praktor_p2p_local.ps1`

其中：

- `praktor_p2p_ci.yml` 是 full 回归入口
- `praktor_p2p_smoke_ci.yml` 是 smoke 入口，复用 full workflow，只覆盖更小的构建目标和测试筛选

full 入口默认目标是远端 Linux release 构建，执行顺序固定为：

1. `vcpkg install`
2. `cmake --preset`
3. `cmake --build --preset`
4. `ctest --preset`

默认变量：

- `WORKING_DIR=.`
- `CMAKE_PRESET=linux-release-user`
- `TEST_PRESET=linux-release-user`
- `BUILD_TARGET=test_p2p test_mesh test_mesh_faults test_mesh_multihop test_mesh_paths test_fake_dns test_ip_stack test_nat test_session test_tunnel test_socks5`
- `VCPKG_TRIPLET=x64-linux`
- `VCPKG_INSTALL_ROOT=vcpkg_installed`
- `VCPKG_COMMAND=/opt/vcpkg/vcpkg`
- `VCPKG_COMMAND_PREFIX=env -u LD_PRELOAD VCPKG_FORCE_SYSTEM_BINARIES=1`
- `COMMAND_PREFIX=env -u LD_PRELOAD`
- `TEST_COMMAND_PREFIX=env LD_LIBRARY_PATH=/opt/turbonet/lib`
- `BUILD_ARGS=-j 1`
- `CTEST_ARGS=`

最上层统一入口是：

```powershell
.\run_praktor_p2p.ps1 -Target Local -Action Run -Mode Smoke
.\run_praktor_p2p.ps1 -Target Local -Action Run -Mode Full
.\run_praktor_p2p.ps1 -Target Remote -Action Run -Mode Smoke
.\run_praktor_p2p.ps1 -Target Remote -Action Status -Mode Full
```

若要把远端 `Praktor smoke` 和 `meshd` TUN/status 检查串成一条 smoke 命令，可直接用：

```powershell
.\run_remote_p2p_smoke.ps1 -Action Run
.\run_remote_p2p_smoke.ps1 -Action Status
.\run_remote_p2p_smoke.ps1 -Action Logs
.\run_remote_p2p_smoke.ps1 -Action Stop
```

这个组合入口会依次执行：

1. `Praktor smoke`
2. `meshd` 远端 `tmux + TUN + status_file` 检查

若要把远端两节点 `meshd` bring-up 也并入同一条 smoke 命令，可追加：

```powershell
.\run_remote_p2p_smoke.ps1 -Action Run -WithMeshdPair
.\run_remote_p2p_smoke.ps1 -Action Status -WithMeshdPair
```

此时会额外执行：

3. `mesh.eu.yaml + mesh.local.yaml` 两节点 `meshd` pair 检查

若要把 public STUN 回归也并入同一条 smoke 命令，可追加：

```powershell
.\run_remote_p2p_smoke.ps1 -Action Run -WithPublicStun
.\run_remote_p2p_smoke.ps1 -Action Run -WithMeshdPair -WithPublicStun
```

默认走 `two-node` 场景；若需覆盖，可传：

- `-RemotePublicStunScenario two-node|three-node|matrix`
- `-RemotePublicStunUrl stun:host:port`
- `-RemotePublicStunAdvertiseIp <ip>`
- `-RemoteSessionPrefix <prefix>` 用于同机并发时隔离 `tmux session` 与状态文件

若不想记这些开关组合，也可直接选 profile：

```powershell
.\run_remote_p2p_smoke.ps1 -Action Run -Profile Core
.\run_remote_p2p_smoke.ps1 -Action Run -Profile Pair
.\run_remote_p2p_smoke.ps1 -Action Run -Profile Stun
.\run_remote_p2p_smoke.ps1 -Action Run -Profile StunThreeNode
.\run_remote_p2p_smoke.ps1 -Action Run -Profile StunMatrix
.\run_remote_p2p_smoke.ps1 -Action Run -Profile FullSmoke
.\run_remote_p2p_smoke.ps1 -Action Run -Profile FullThreeNode
.\run_remote_p2p_smoke.ps1 -Action Run -Profile FullMatrix
```

当前 profile 语义：

- `Core`: `Praktor smoke + 单节点 meshd`
- `Pair`: `Core + 两节点 meshd pair`
- `Stun`: `Core + public STUN two-node`
- `StunThreeNode`: `Core + public STUN three-node`
- `StunMatrix`: `Core + public STUN matrix`
- `FullSmoke`: `Core + 两节点 meshd pair + public STUN two-node`
- `FullThreeNode`: `Core + 两节点 meshd pair + public STUN three-node`
- `FullMatrix`: `Core + 两节点 meshd pair + public STUN matrix`

说明：

- 这些 profile 会固定 `RemotePublicStunScenario`
- 若 profile 与显式传入的 `-RemotePublicStunScenario` 冲突，脚本会直接报错，避免表面跑的是一个档位，实际执行的是另一个场景
- 若需在同一台远端机器上并发跑多条 smoke，可给每条命令加不同的 `-RemoteSessionPrefix`
- public STUN 现在也走远端 `tmux` runner；`Status/Logs/Stop` 不再只是提示语，而能查看真实 session/log

远端 Linux 直接运行示例：

```bash
/root/code/praktor/build/linux-gcc-release/bin/praktor -f /root/code/turbo-p2p/praktor_p2p_ci.yml --color never
```

远端 Linux smoke 运行示例：

```bash
/root/code/praktor/build/linux-gcc-release/bin/praktor -f /root/code/turbo-p2p/praktor_p2p_smoke_ci.yml --color never
```

若要用 `tmux` 托管远端长任务，可直接用：

```bash
bash /root/code/turbo-p2p/run_praktor_p2p_tmux.sh --mode smoke
bash /root/code/turbo-p2p/run_praktor_p2p_tmux.sh --action wait --mode smoke
bash /root/code/turbo-p2p/run_praktor_p2p_tmux.sh --mode full
bash /root/code/turbo-p2p/run_praktor_p2p_tmux.sh --action status --mode full
```

若要切换到 Windows 本地开发构建，可覆盖变量：

```bash
praktor -f praktor_p2p_ci.yml -i CMAKE_PRESET=win-dev-user -i TEST_PRESET=win-dev-user -i VCPKG_TRIPLET=x64-windows -i VCPKG_INSTALL_ROOT=vcpkg_installed -i VCPKG_COMMAND=vcpkg -i VCPKG_COMMAND_PREFIX= -i COMMAND_PREFIX= -i TEST_COMMAND_PREFIX= -i BUILD_ARGS=
```

Windows 本地更建议直接用脚本入口：

```powershell
$env:VSDEVCMD = '<path-to-VsDevCmd.bat>'
.\run_praktor_p2p_local.ps1 -Action Run -Mode Smoke
.\run_praktor_p2p_local.ps1 -Action Run -Mode Full
```

如果想统一走顶层入口，对应写法是：

```powershell
$env:VSDEVCMD = '<path-to-VsDevCmd.bat>'
.\run_praktor_p2p.ps1 -Target Local -Action Validate -Mode Smoke
.\run_praktor_p2p.ps1 -Target Local -Action Run -Mode Full
.\run_praktor_p2p.ps1 -Target Remote -Action Run -Mode Smoke
```

说明：

- `run_praktor_p2p_local.ps1` 在 `Mode Smoke` 且未显式传 `-CtestArgs` 时，会自动注入 Windows `cmd.exe` 兼容的 smoke 筛选：`-R ^(test_p2p^|test_mesh_paths)$`

若只想做本地 workflow 校验，不触发构建：

```powershell
$env:VSDEVCMD = '<path-to-VsDevCmd.bat>'
.\run_praktor_p2p_local.ps1 -Action Validate -Mode Smoke
```

脚本本质上仍是把 `VSDEVCMD` 作为环境变量传入，再让各 task 的前缀在 `cmd.exe` 里调用它；若你确实要手动覆盖，等价形式如下：

```powershell
$env:VSDEVCMD = '<path-to-VsDevCmd.bat>'
praktor -f praktor_p2p_ci.yml `
  -i CMAKE_PRESET=win-dev-user `
  -i TEST_PRESET=win-dev-user `
  -i VCPKG_TRIPLET=x64-windows `
  -i VCPKG_INSTALL_ROOT=vcpkg_installed `
  -i VCPKG_COMMAND=vcpkg `
  -i 'VCPKG_COMMAND_PREFIX=call "%VSDEVCMD%" -arch=x64 -host_arch=x64 >nul &&' `
  -i 'COMMAND_PREFIX=call "%VSDEVCMD%" -arch=x64 -host_arch=x64 >nul &&' `
  -i 'TEST_COMMAND_PREFIX=call "%VSDEVCMD%" -arch=x64 -host_arch=x64 >nul &&' `
  -i BUILD_ARGS=
```

若只想重跑某个测试，可覆盖 `CTEST_ARGS`：

```bash
/root/code/praktor/build/linux-gcc-release/bin/praktor -f /root/code/turbo-p2p/praktor_p2p_ci.yml -i CTEST_ARGS="-R ^test_mesh_paths$" --color never
```

若通过 `tmux` runner 覆盖变量，可重复传 `--var`：

```bash
bash /root/code/turbo-p2p/run_praktor_p2p_tmux.sh --mode full --var "CTEST_ARGS=-R ^test_mesh_paths$"
```

说明：

- `vcpkg install` 被放在 `cmake --preset` 之前，避免 preset 配置阶段缺依赖。
- smoke workflow 通过 `uses: ./praktor_p2p_ci.yml` 复用 full 流程，只覆盖 `BUILD_TARGET=test_p2p test_mesh_paths` 与对应 `CTEST_ARGS`，避免维护两份独立任务链。
- `run_praktor_p2p.ps1` 是统一路由入口：`Target=Local` 时转发给 `run_praktor_p2p_local.ps1`，`Target=Remote` 时通过 `ssh` 调 `run_praktor_p2p_tmux.sh`；`Remote + Action=Run` 会自动执行 `start` 再 `wait`。
- smoke workflow 现在会把 `CMAKE_PRESET`、`VCPKG_*`、`COMMAND_PREFIX`、`TEST_COMMAND_PREFIX`、`BUILD_ARGS`、`CTEST_ARGS` 等变量继续转发给 nested full workflow，所以本地 Windows 覆盖和远端 Linux 默认值都能走同一条入口。
- `run_praktor_p2p_tmux.sh` 只负责远端 `tmux` 生命周期管理，支持 `start/status/logs/wait/stop`，实际构建/测试逻辑仍由 workflow YAML 定义。
- `run_praktor_p2p_local.ps1` 只负责本地 Windows 调用参数组装与 `VSDEVCMD` 注入，实际构建/测试逻辑仍由 workflow YAML 定义。
- 各任务显式设置了 `working_dir`，相对路径以 workflow 文件所在目录解析，所以不再依赖调用方先 `cd` 到仓库根目录。
- `Praktor` 在 Windows 上通过 `cmd.exe /c` 执行 task command，所以本地 MSVC 工具链初始化应通过环境变量 `VSDEVCMD` 配合 `call "%VSDEVCMD%" ... &&` 前缀完成，而不是把 Visual Studio 路径硬编码进 workflow。
- `Praktor` 的 shell 默认超时是 `30000ms`，所以 workflow 已为 `vcpkg_install`、`configure`、`build`、`test` 显式设置更长 timeout，避免长构建或 `test_mesh` 这类长测例被 executor 误杀。
- 默认 `BUILD_TARGET` 只覆盖当前测试目标，避免示例程序把 CI 结论污染掉；若要做全量产物构建，可覆盖成 `BUILD_TARGET=all`。
- `configure` 默认带 `--fresh`，避免远端复用旧 build cache 时把 manifest 模式、toolchain 路径等历史状态带进本次 CI。
- Linux 默认让 `vcpkg install` 强制使用系统二进制工具链，避免 `x265` 之类旧端口在 `cmake 4.x` 下配置失败。
- Linux 默认用 `-j 1`，是为了在小内存远端机上避免再次把机器打进 swap 风暴。
- 若测试机上的 `TurboNet` 不在 `/opt/turbonet/lib`，请覆盖 `TEST_COMMAND_PREFIX`。
