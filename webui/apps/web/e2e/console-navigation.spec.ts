import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { login, navigate } from './fixture';

test('慢请求、重试、快速连续导航、键盘焦点及减少动态效果', async ({ page }) => {
  await login(page);
  const nav = page.getByRole('list');
  const subscription = nav.getByRole('link', { name: '订阅与下载', exact: true });
  const main = page.getByRole('main');
  const region = page.locator('[data-route-content]');
  const search = page.getByRole('textbox', { name: '搜索后台页面' });
  await search.fill('节点与订阅');
  await expect(subscription).toBeVisible();
  await search.clear();

  let release: () => void = () => {};
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route(
    '**/nc/api/nodes',
    async (route) => {
      await delayed;
      await route.fulfill({ status: 502, contentType: 'application/json', body: '{}' });
    },
    { times: 1 },
  );

  await subscription.focus();
  await page.keyboard.press('Enter');
  await expect(main.getByRole('status', { name: '正在读取节点' })).toBeVisible();
  await expect(region).toHaveAttribute('data-route-kind', 'forward');
  await expect(main).toBeFocused();
  release();
  await expect(main.getByRole('alert')).toContainText('读取失败');
  await main.getByRole('button', { name: '重试' }).click();
  await expect(main.getByRole('heading', { name: '订阅与下载', level: 1 })).toBeVisible();

  let releaseHosts: () => void = () => {};
  const slowHosts = new Promise<void>((resolve) => {
    releaseHosts = resolve;
  });
  await page.route(
    '**/nc/api/config',
    async (route) => {
      await slowHosts;
      await route.continue();
    },
    { times: 1 },
  );
  await nav.getByRole('link', { name: '主机', exact: true }).click();
  await expect(main.locator('[data-loading-kind]')).toBeVisible();
  await navigate(page, '服务管理');
  releaseHosts();
  await expect(main.getByRole('heading', { name: '服务管理', level: 1 })).toBeVisible();
  await page.goBack();
  await expect(main.getByRole('heading', { name: '主机', level: 1 })).toBeVisible();
  await expect(region).toHaveAttribute('data-route-kind', 'back');
  await page.goForward();
  await expect(main.getByRole('heading', { name: '服务管理', level: 1 })).toBeVisible();

  await page.emulateMedia({ reducedMotion: 'reduce' });
  await expect(page.locator('html')).toHaveAttribute('data-motion-screen', 'off');
  await navigate(page, '分组');
  const header = main.getByRole('heading', { name: '分组', level: 1 }).locator('../..');
  expect(await header.evaluate((element) => getComputedStyle(element).animationName)).toBe('none');
});

test('主机编辑抽屉保留草稿、可用键盘关闭，权重刷新时保留输入', async ({ page }) => {
  await login(page);
  await navigate(page, '主机');
  await page.getByRole('textbox', { name: '搜索列表' }).fill('no-matching-host');
  await expect(page.getByText('没有匹配的记录。请调整筛选条件。')).toBeVisible();
  await page.getByRole('textbox', { name: '搜索列表' }).clear();
  const add = page.getByRole('button', { name: '新建', exact: true });
  await add.click();
  const drawer = page.getByRole('dialog', { name: '新建 · 主机' });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByRole('tab')).toHaveCount(4);
  await drawer.getByRole('textbox', { name: '备注' }).fill('draft');
  await expect(page.locator('[role="log"] [role="img"]')).toHaveCount(0);
  const audit = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
    .analyze();
  expect(audit.violations.map(({ id }) => id)).toEqual([]);
  await page.keyboard.press('Escape');
  await expect(page.getByRole('alertdialog', { name: '放弃修改' })).toBeVisible();
  await page.getByRole('button', { name: '继续编辑' }).click();
  await expect(drawer.getByRole('textbox', { name: '备注' })).toHaveValue('draft');
  await drawer.getByRole('button', { name: '关闭抽屉' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: '放弃修改' }).click();
  await expect(drawer).toBeHidden();
  await expect(add).toBeFocused();

  await navigate(page, '配置中心');
  const field = page.getByRole('textbox', { name: /XHTTP/ });
  await field.fill('81');
  await expect(page.getByText('权重合计 · 101%')).toBeVisible();
  await page.getByRole('button', { name: '刷新', exact: true }).click();
  await expect(field).toHaveValue('81');
  await expect(page.getByRole('button', { name: '预览变更', exact: true })).toBeDisabled();
});

test('服务任务跨页可见，运维页提供版本管理和任务详情', async ({ page }) => {
  await login(page);
  await navigate(page, '服务管理');
  const nginx = page.getByRole('row', { name: /^nginx/ });
  await nginx.getByRole('button', { name: '校验并重载', exact: true }).click();
  let release: () => void = () => {};
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route(
    '**/nc/api/jobs/*',
    async (route) => {
      await delayed;
      await route.continue();
    },
    { times: 1 },
  );
  await page
    .getByRole('alertdialog')
    .getByRole('button', { name: '确认执行', exact: true })
    .click();
  await expect(page.getByRole('alertdialog')).toHaveCount(0);
  await expect(page.getByRole('link', { name: /任务执行中/ })).toBeVisible();
  await navigate(page, '运行总览');
  await expect(page.getByRole('link', { name: /任务执行中/ })).toBeVisible();
  release();
  const status = page.getByRole('link', { name: /任务完成|任务执行中/ });
  await expect(status).toBeVisible();
  await status.click();
  await expect(page.getByRole('heading', { name: 'nodectl 版本管理' })).toBeVisible();
  const version = page.getByRole('textbox', { name: /^目标版本/ });
  await version.fill('bad-version');
  await expect(version).toHaveAttribute('aria-invalid', 'true');
  await version.fill('v0.8.0');
  await page.getByRole('button', { name: '重新安装当前版本', exact: true }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: '取消', exact: true }).click();
  const task = page.getByRole('row', { name: /service-reload/ }).first();
  await task.getByRole('button', { name: '查看详情' }).click();
  await expect(page.getByText(/service-reload · completed ·/)).toBeVisible();
});
