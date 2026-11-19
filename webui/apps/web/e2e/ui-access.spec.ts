import { test, expect } from '@playwright/test';
import { login, navigate } from './fixture';

test('浏览器认证只在面板设置编辑，设备配置只在客户端下载', async ({ page }) => {
  await login(page);
  await navigate(page, '面板设置');
  const ttl = page.getByRole('textbox', { name: '认证缓存时间（秒）', exact: true });
  const save = page.getByRole('button', { name: '保存', exact: true });
  const originalTtl = await ttl.inputValue();
  const username = 'ux-fixture';
  try {
    await ttl.fill('59');
    await expect(ttl).toHaveAttribute('aria-invalid', 'true');
    await expect(save).toBeDisabled();
    await ttl.fill('600');
    if (originalTtl !== '600') {
      await save.click();
      await expect(page.getByText('代理认证设置已保存。')).toBeVisible();
    }

    await navigate(page, '客户端');
    await expect(page.getByRole('textbox', { name: '认证缓存时间（秒）' })).toHaveCount(0);
    await page.getByRole('button', { name: '新建用户', exact: true }).click();
    const create = page.getByRole('dialog', { name: '新建用户' });
    await create.getByLabel('用户名', { exact: true }).fill(username);
    await create.getByLabel('密码', { exact: true }).fill('isolated-browser-test');
    await create.getByRole('button', { name: '新建用户', exact: true }).click();
    await expect(create).toBeHidden();
    const open = async () => {
      await page
        .getByRole('row', { name: new RegExp(username) })
        .getByRole('button', { name: '管理', exact: true })
        .click();
      return page.getByRole('dialog', { name: username, exact: true });
    };
    let account = await open();
    await account.getByLabel('设备名称', { exact: true }).fill('Chromium fixture');
    await account.getByRole('button', { name: '登记设备', exact: true }).click();
    await expect(account.getByRole('row', { name: /^Chromium fixture/ })).toBeVisible();
    await account.getByRole('button', { name: '关闭抽屉' }).click();

    await navigate(page, '面板设置');
    await page.getByRole('button', { name: '启用认证', exact: true }).click();
    await page
      .getByRole('alertdialog')
      .getByRole('button', { name: '启用认证', exact: true })
      .click();
    await expect(page.getByRole('button', { name: '停用认证', exact: true })).toBeVisible();
    await navigate(page, '订阅与下载');
    await expect(page.getByRole('button', { name: '导出 Xray JSON' })).toHaveCount(0);
    await page.getByRole('link', { name: '前往客户端下载' }).click();
    await expect(page.getByRole('heading', { name: '客户端', level: 1 })).toBeVisible();
    account = await open();
    const pendingDownload = page.waitForEvent('download');
    await account.getByRole('button', { name: '导出 Mihomo YAML', exact: true }).click();
    expect((await pendingDownload).suggestedFilename()).toBe('nodectl-mihomo.yaml');
  } finally {
    await page.evaluate(
      async ({ username, originalTtl }) => {
        const session = await fetch('/admin/api/session');
        if (!session.ok) return;
        const value: unknown = await session.json();
        if (
          !value ||
          typeof value !== 'object' ||
          !('csrf' in value) ||
          typeof value.csrf !== 'string'
        )
          return;
        const csrf = value.csrf;
        const update = (body: object) =>
          fetch('/admin/api/proxy-access', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
            body: JSON.stringify(body),
          });
        await update({ action: 'settings', enabled: false, ttl_seconds: Number(originalTtl) });
        await update({ action: 'delete', usernames: [username] });
      },
      { username, originalTtl },
    );
  }
});
