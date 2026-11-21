# legacy

这里保留**已退役**的历史脚本，只为留痕与考古，正式流程不再调用：

| 文件 | 退役原因 | 现行替代 |
|---|---|---|
| `gateway_sync.py` | 只同步小档，片数口径与三档不一致 | `tools/gateway_all.py` + `tools/gateway_align.py` |
| `log_step.py` | 往固定 Issue 刷进度，把手机通知变成噪声；告警已有防抖与单一 Issue 通道 | `.github/workflows/daily.yml` 的 step 日志 + `tools/alert.py` |

**不要**在这些文件上继续加功能；需要恢复就从 git 历史里取。
