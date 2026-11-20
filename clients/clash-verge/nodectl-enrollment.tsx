// SPDX-License-Identifier: GPL-3.0-only
import { Alert, Button } from '@mui/material'
import { invoke } from '@tauri-apps/api/core'
import { useEffect, useState } from 'react'

const labels: Record<string, string> = {
  'awaiting-login': '配置已导入。用管理员分配给你的账号登录。',
  'login-required': '设备的认证已过期。请用原账号重新登录。',
  'enrollment-expired': '这份配置超过 24 小时未激活。请重新领取后登录。',
  revoked: '此设备的订阅已撤销或失效。请联系管理员。',
  unavailable: '账号或客户端当前不可用。请联系管理员。',
  'quota-exhausted': '此账号的流量额度已用完。',
  active: '已认证，个人订阅已启用。',
  offline: '暂时无法同步认证状态。客户端会自动重试。',
}

export function NodectlEnrollmentNotice() {
  const [state, setState] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [browserError, setBrowserError] = useState(false)

  useEffect(() => {
    let stopped = false
    let timeout: ReturnType<typeof setTimeout> | undefined
    async function poll() {
      const result = await invoke<string | null>('nodectl_state').catch(
        () => 'offline',
      )
      if (stopped) return
      setState(result)
      timeout = setTimeout(poll, result === 'active' ? 15000 : 3000)
    }
    void poll()
    return () => {
      stopped = true
      clearTimeout(timeout)
    }
  }, [])

  if (!state || !labels[state]) return null
  const login = state === 'awaiting-login' || state === 'login-required'
  const renew = state === 'enrollment-expired'
  return (
    <Alert
      severity={state === 'active' ? 'success' : login ? 'info' : 'warning'}
      action={
        (login || renew) && (
          <Button
            color="inherit"
            disabled={busy}
            onClick={async () => {
              setBusy(true)
              setBrowserError(false)
              try {
                await invoke(renew ? 'nodectl_renew_expired' : 'nodectl_open_login')
              } catch {
                setBrowserError(true)
              } finally {
                setBusy(false)
              }
            }}
          >
            {renew ? '重新领取此设备' : '启用代理并打开认证页'}
          </Button>
        )
      }
    >
      {labels[state]}
      {browserError && ' 操作未完成，请稍后重试。'}
    </Alert>
  )
}
