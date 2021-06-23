## 认证状态同步容器

结构设计如下

 - mqtt 负责实时同步变更的用户数据，新增/添加用户记录，调用 auth
 - syncNasClients 负责从微云间拉取用户信息，新增/添加用户记录
 - syncRouterOnlineDevices 负责同步终端在线态，更新 IP，Online 标记
 - syncRouterAuthUsers 负责同步终端认证态更，更新 Auth 标记
 - checkDeviceAuthStatus 检查 Online = true && Auth = false 的设备，帮助他们进行认证
    - 需要保证在执行该函数的前序，执行 syncNasClients 以及 syncRouterOnlineDevices && syncRouterAuthUsers，顺序不可颠倒
    - 针对符合条件的设备，调用 auth 进行认证
 - auth 单个用户认证

自定义定时器

 - checkDeviceAuthStatus 建议 30s 执行一次
 - syncNasClients 建议第一次执行，以及 间隔 30 分钟执行一次
 - syncRouterOnlineDevices && syncRouterAuthUsers 间隔 1 分钟执行一次
