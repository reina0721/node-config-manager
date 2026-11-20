import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test, expect, type Page } from '@playwright/test';
import { login, navigate } from './fixture';

async function access<T>(page: Page, path = 'proxy-access', body?: object): Promise<T> {
  return page.evaluate(
    async ({ path, body }) => {
      let init: RequestInit | undefined;
      if (body) {
        const session = await fetch('/nc/api/session');
        if (!session.ok) throw new Error('Fixture session unavailable');
        const { csrf } = (await session.json()) as { csrf: string };
        init = {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
          body: JSON.stringify(body),
        };
      }
      const response = await fetch('/nc/api/' + path, init);
      if (!response.ok) throw new Error('Fixture API failed with HTTP ' + response.status);
      return (await response.json()) as T;
    },
    { path, body },
  );
}

test('认证有效期只在面板设置编辑', async ({ page }) => {
  await login(page);
  await navigate(page, '面板设置');
  const ttl = page.getByRole('textbox', { name: '认证缓存时间（秒）', exact: true });
  const save = page.getByRole('button', { name: '保存', exact: true });
  const originalTtl = await ttl.inputValue();
  await ttl.fill('59');
  await expect(ttl).toHaveAttribute('aria-invalid', 'true');
  await expect(save).toBeDisabled();
  await ttl.fill(originalTtl);
  await navigate(page, '客户端');
  await expect(page.getByRole('textbox', { name: '认证缓存时间（秒）' })).toHaveCount(0);
});

test('只从共享客户端领取配置，已有设备可查看且原订阅有效', async ({ page }) => {
  test.setTimeout(180_000);
  await login(page);
  const username = 'ux-' + randomUUID();
  const clientName = '浏览器验收客户端 ' + username.slice(0, 11);
  const initial = await access<{ enabled: boolean; ttl_seconds: number }>(page);
  let clientId: string | undefined;

  try {
    if (!initial.enabled)
      await access(page, 'proxy-access', { ...initialSettings(initial), enabled: true });
    await access(page, 'proxy-access', {
      action: 'create',
      users: [{ username, password: 'isolated-browser-test', device_limit: 2 }],
    });
    const { clients } = await access<{ clients: { id: string; name: string }[] }>(
      page,
      'proxy-access',
      {
        action: 'save-client',
        name: clientName,
        usernames: [username],
        inbounds: [],
        links: [],
      },
    );
    clientId = clients.find(({ name }) => name === clientName)?.id;
    if (!clientId) throw new Error('Missing fixture client');
    const { created_device_id: legacy } = await access<{ created_device_id: string }>(
      page,
      'proxy-access',
      {
        action: 'create-device',
        username,
        label: '已有设备',
        client: clientId,
      },
    );
    const profilePath = 'proxy-access/profile/' + legacy + '/subscriptions';
    const previous = await access<{ content: string }>(page, profilePath);
    await navigate(page, '客户端');
    await expect(page.getByRole('tab', { name: '共享客户端' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    await expect(page.getByText('原有设备配置', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '旧设备配置', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '设备与下载', exact: true })).toHaveCount(0);
    const row = page
      .getByRole('grid', { name: '共享客户端' })
      .getByRole('row')
      .filter({ hasText: clientName });
    const entry = row.getByRole('button', { name: '领取与下载', exact: true });
    await entry.click();
    const drawer = page.getByRole('dialog', { name: '领取与下载', exact: true });
    await expect(drawer.getByLabel('用户名', { exact: true })).toHaveCount(0);
    await expect(drawer.getByText(/安装名额/)).toHaveCount(0);
    const sharedFile = drawer.getByRole('button', { name: '下载公共配置文件', exact: true });
    const downloadShared = async () => {
      const [file] = await Promise.all([page.waitForEvent('download'), sharedFile.click()]);
      expect(file.suggestedFilename()).toBe(`nodectl-${clientId}.yaml`);
      return readFile(await file.path(), 'utf8');
    };
    const descriptor = await downloadShared();
    expect(await downloadShared()).toBe(descriptor);
    expect(JSON.parse(descriptor)).toEqual({
      nodectl: { version: 1, origin: expect.any(String), client: clientId,
        enrollment: expect.any(String), name: clientName },
    });
    await drawer.getByText('个人订阅与旧版客户端', { exact: true }).click();
    const mihomo = drawer.getByRole('button', { name: '下载 Mihomo 配置', exact: true });
    await expect(mihomo).toBeEnabled();
    const pending = page.waitForEvent('download');
    await mihomo.focus();
    await page.keyboard.press('Enter');
    expect((await pending).suggestedFilename()).toBe('nodectl-mihomo-weighted.yaml');
    await expect(drawer.getByRole('button', { name: '为另一台设备下载' })).toBeEnabled();
    await page.keyboard.press('Escape');
    await expect(drawer).toBeHidden();
    await expect(entry).toBeFocused();

    await page.getByRole('tab', { name: '用户与设备' }).click();
    await page
      .getByRole('row', { name: new RegExp(username) })
      .getByRole('button', { name: '管理', exact: true })
      .click();
    const account = page.getByRole('dialog', { name: username, exact: true });
    await expect(account.getByText('已有设备', { exact: true })).toBeVisible();
    await expect(account.getByText('设备码', { exact: true })).toBeVisible();
    await expect(account.getByRole('button', { name: '撤销设备', exact: true })).toBeEnabled();
    await expect(account.getByRole('button', { name: /下载|导出.*配置/ })).toHaveCount(0);
    expect(await access(page, profilePath)).toEqual(previous);
  } finally {
    if (clientId) await access(page, 'proxy-access', { action: 'delete-client', id: clientId });
    await access(page, 'proxy-access', { action: 'delete', usernames: [username] });
    if (!initial.enabled) await access(page, 'proxy-access', initialSettings(initial));
  }
});

function initialSettings({ enabled, ttl_seconds }: { enabled: boolean; ttl_seconds: number }) {
  return { action: 'settings', enabled, ttl_seconds };
}
