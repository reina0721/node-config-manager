'use strict';

const button = document.querySelector('#claim');
const another = document.querySelector('#another');
const message = document.querySelector('#message');
const formats = document.querySelector('#formats');
const subscription = document.querySelector('#subscription');
const key = location.hash.slice(1);
const valid = /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(key);
const storageKey = 'nodectl-claim:' + key;
let request;
try {
  request = valid ? localStorage.getItem(storageKey) : null;
} catch {
  request = null;
}

function useRequest(id) {
  request = id;
  try {
    localStorage.setItem(storageKey, id);
  } catch {
    // The current page can still retry the same request without storage.
  }
}

if (!valid) {
  button.disabled = true;
  message.textContent = '请打开管理员发给你的客户端领取链接。';
}

button.addEventListener('click', async () => {
  if (!valid || button.disabled) return;
  button.disabled = true;
  another.hidden = true;
  message.textContent = '正在领取配置…';
  try {
    if (!request) useRequest(crypto.randomUUID());
    const response = await fetch('/nodes/claim', {
      method: 'POST',
      credentials: 'omit',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, request }),
    });
    if (response.status === 429) {
      message.textContent = '当前领取请求较多，请稍后重试。';
      return;
    }
    if (response.status === 404) {
      message.textContent = '当前领取记录已失效或链接不可用，请联系管理员。';
      another.hidden = false;
      formats.hidden = true;
      return;
    }
    if (!response.ok) throw new Error();
    const result = await response.json();
    subscription.value = new URL(result.mihomo, location.origin).href;
    document.querySelector('#mihomo').href = result.mihomo;
    document.querySelector('#xray').href = result.xray;
    document.querySelector('#portal').href = result.browser_login;
    formats.hidden = false;
    another.hidden = false;
    message.textContent = '配置已领取。请导入并启用节点，然后打开认证页。';
  } catch {
    message.textContent = '暂时无法领取，请稍后重试。';
  } finally {
    button.disabled = false;
  }
});

another.addEventListener('click', () => {
  useRequest(crypto.randomUUID());
  formats.hidden = true;
  another.hidden = true;
  button.click();
});

document.querySelector('#copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(subscription.value);
    message.textContent = '已复制 Mihomo 订阅地址。';
  } catch {
    subscription.focus();
    subscription.select();
    message.textContent = '请复制已选中的订阅地址。';
  }
});
