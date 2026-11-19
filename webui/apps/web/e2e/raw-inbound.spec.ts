import { expect, test } from '@playwright/test';
import { login, navigate } from './fixture';

test('Raw TCP REALITY 隐藏路径、检查端口冲突并可返回原草稿', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);
  await navigate(page, '入站');

  await page.getByRole('button', { name: '新建', exact: true }).click();
  const editor = page.getByRole('dialog', { name: '新建 · 入站' });
  const preview = editor.getByRole('button', { name: '预览变更', exact: true });
  await expect(preview).toBeDisabled();
  await editor.getByRole('textbox', { name: '备注', exact: true }).fill('Raw REALITY 28436');
  await editor.getByRole('button', { name: '传输', exact: false }).click();
  await page.getByRole('option', { name: 'Raw TCP', exact: true }).click();
  await editor.getByRole('button', { name: '安全', exact: false }).click();
  await page.getByRole('option', { name: 'REALITY', exact: true }).click();
  await expect(editor.getByRole('textbox', { name: '传输路径', exact: true })).toHaveCount(0);

  const port = editor.getByRole('textbox', { name: '端口', exact: true });
  await port.fill('8443');
  await expect(port).toHaveAttribute('aria-invalid', 'true');
  await expect(preview).toBeDisabled();
  await port.fill('28436');
  await expect(preview).toBeEnabled();

  // The disabled draft previews without modifying listeners in the browser fixture.
  await expect(editor.getByRole('switch', { name: '启用', exact: true })).not.toBeChecked();
  await preview.click();
  await page.getByRole('button', { name: '返回编辑', exact: true }).click();
  await expect(port).toHaveValue('28436');
  await expect(editor.getByRole('textbox', { name: '备注', exact: true })).toHaveValue(
    'Raw REALITY 28436',
  );
});
