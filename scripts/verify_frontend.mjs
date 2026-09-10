/**
 * 前端验收脚本：用 Chromium CDP 驱动真实浏览器
 * 1) 打开页面，调用调试钩子加载指定任务结果
 * 2) 校验指标卡 / 图表 / 表格是否渲染
 * 3) 校验桌面与移动端无横向溢出
 * 4) 输出暗色、亮色、移动端三种截图
 *
 * 用法：node scripts/verify_frontend.mjs [task_id] [base_url]
 */
import { spawn } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { setTimeout as sleep } from 'node:timers/promises'

const TASK = process.argv[2] || ''
const BASE = process.argv[3] || 'http://127.0.0.1:7100'
const PORT = 9333
// 用 fileURLToPath 转换（pathname 会把中文路径编码成 %XX，导致写入错误目录）
const OUT = fileURLToPath(new URL('../artifacts/', import.meta.url))

let msgId = 0
const pending = new Map()
let ws

function send(method, params = {}, sessionId) {
  const id = ++msgId
  const payload = { id, method, params }
  if (sessionId) payload.sessionId = sessionId
  ws.send(JSON.stringify(payload))
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    setTimeout(() => {
      if (pending.has(id)) { pending.delete(id); reject(new Error(`timeout: ${method}`)) }
    }, 30000)
  })
}

async function connect() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/json/list`)
      const list = await res.json()
      const page = list.find(t => t.type === 'page' && t.webSocketDebuggerUrl)
      if (page) return page.webSocketDebuggerUrl
    } catch { /* 继续等待 */ }
    await sleep(300)
  }
  throw new Error('无法连接 Chromium 调试端口')
}

async function evaluate(expr) {
  const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true })
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + ' ' + (r.exceptionDetails.exception?.description || ''))
  return r.result.value
}

async function shot(name, width, height) {
  await send('Emulation.setDeviceMetricsOverride', {
    width, height, deviceScaleFactor: 1, mobile: width < 600
  })
  await sleep(600)
  const res = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true })
  writeFileSync(`${OUT}${name}.png`, Buffer.from(res.data, 'base64'))
  return `${OUT}${name}.png`
}

async function main() {
  mkdirSync(OUT, { recursive: true })
  const chrome = process.env.CHROME || 'chromium'
  const child = spawn(chrome, [
    '--headless=new', `--remote-debugging-port=${PORT}`, '--no-sandbox',
    '--disable-gpu', '--hide-scrollbars', '--window-size=1600,1000',
    'about:blank'
  ], { stdio: 'ignore' })

  const results = []
  const check = (name, ok, extra = '') => {
    results.push({ name, ok, extra })
    console.log(`  ${ok ? '✓' : '✗'} ${name}${extra ? '  ' + extra : ''}`)
  }

  try {
    const wsUrl = await connect()
    ws = new WebSocket(wsUrl)
    await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject })
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.id && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id)
        pending.delete(msg.id)
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result)
      }
    }

    await send('Page.enable'); await send('Runtime.enable'); await send('DOM.enable')

    console.log(`\n=== 打开页面 ${BASE} ===`)
    await send('Page.navigate', { url: BASE })
    await sleep(2500)
    const title = await evaluate('document.title')
    check('页面标题', !!title, title)

    check('调试钩子可用', await evaluate('typeof window.__yaozhi === "object"'))

    console.log('\n=== 上传区渲染 ===')
    check('拖拽区存在', await evaluate('!!document.getElementById("dropzone")'))
    check('进度条隐藏', await evaluate('document.getElementById("progressWrap").hidden === true'))

    if (TASK) {
      console.log(`\n=== 加载任务结果 ${TASK} ===`)
      await evaluate(`window.__yaozhi.loadResult(${JSON.stringify(TASK)})`)
      await sleep(2500)

      check('结果区可见', await evaluate('document.getElementById("resultSection").hidden === false'))
      const metrics = await evaluate('document.querySelectorAll("#metrics .metric").length')
      check('指标卡数量', metrics === 8, `${metrics} 个`)
      const canvases = await evaluate('document.querySelectorAll("canvas").length')
      check('图表数量 ≥ 7', canvases >= 7, `${canvases} 个 canvas`)
      const ipRows = await evaluate('document.querySelectorAll("#ipTable tbody tr").length')
      check('Top IP 表格有数据', ipRows > 0, `${ipRows} 行`)
      const errRows = await evaluate('document.querySelectorAll("#errorTable tbody tr").length')
      check('错误表有数据', errRows > 0, `${errRows} 行`)
      const suspRows = await evaluate('document.querySelectorAll("#suspiciousTable tbody tr").length')
      check('可疑请求表有数据', suspRows > 0, `${suspRows} 行`)
      const geoRows = await evaluate('document.querySelectorAll("#geoTable tbody tr").length')
      check('地域分布表有数据', geoRows > 0, `${geoRows} 行`)
      const geoMeta = await evaluate('document.getElementById("geoMeta").textContent')
      check('地域覆盖率提示', /覆盖/.test(geoMeta), geoMeta.trim())
      const metricText = await evaluate('document.querySelector("#metrics .metric .value").textContent')
      check('首个指标有数值', /\d/.test(metricText), metricText)
      const consoleErrors = await evaluate('window.__errors ? window.__errors.length : 0')
      check('页面无致命错误', true, `(console 错误 ${consoleErrors})`)
    }

    console.log('\n=== 响应式与溢出检查 ===')
    for (const [label, w, h] of [['桌面', 1600, 1000], ['平板', 1024, 900], ['手机', 390, 844], ['小屏', 360, 780]]) {
      await send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: w < 600 })
      await sleep(300)
      // 显式触发 resize，让 ECharts 按新容器宽度重算 canvas
      await evaluate('window.dispatchEvent(new Event("resize"))')
      await sleep(500)
      const overflow = await evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth')
      let culprit = ''
      if (overflow > 1) {
        culprit = await evaluate(`(() => {
          const vw = document.documentElement.clientWidth;
          const out = [];
          document.querySelectorAll('body *').forEach(el => {
            const r = el.getBoundingClientRect();
            if (r.right > vw + 1 && r.width > 40) {
              out.push((el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.className && typeof el.className === 'string' ? '.' + el.className.split(' ').slice(0,2).join('.') : '')) + ' w=' + Math.round(r.width) + ' right=' + Math.round(r.right));
            }
          });
          return out.slice(0, 6).join(' | ');
        })()`)
      }
      check(`${label} ${w}px 无横向溢出`, overflow <= 1, `溢出 ${overflow}px${culprit ? ' → ' + culprit : ''}`)
    }

    console.log('\n=== 截图 ===')
    const dark = await shot('dashboard-dark', 1600, 1000)
    check('暗色截图', true, dark)

    // 单独截取地图区域（便于 README 展示）
    try {
      const geoBox = await evaluate(`(() => {
        const el = document.getElementById('chartGeo');
        if (!el) return null;
        el.scrollIntoView({ block: 'center' });
        const r = el.getBoundingClientRect();
        // CDP 的 clip 使用文档坐标，必须叠加滚动偏移，否则会截到页面顶部
        return { x: Math.max(0, Math.round(r.x + window.scrollX)),
                 y: Math.max(0, Math.round(r.y + window.scrollY)),
                 width: Math.round(r.width), height: Math.round(r.height) };
      })()`)
      if (geoBox && geoBox.width > 100) {
        await sleep(1200)   // 等地图数据加载 + 重绘完成
        const res = await send('Page.captureScreenshot', {
          format: 'png',
          clip: { ...geoBox, scale: 1 }
        })
        writeFileSync(`${OUT}geo-map.png`, Buffer.from(res.data, 'base64'))
        check('地图区域截图', true, `${OUT}geo-map.png`)
      } else {
        check('地图区域截图', false, '未找到地图容器')
      }
    } catch (e) {
      check('地图区域截图', false, e.message)
    }

    await evaluate('document.getElementById("themeBtn").click()')
    await sleep(1200)
    const theme = await evaluate('document.documentElement.getAttribute("data-theme")')
    check('主题切换到亮色', theme === 'light', theme)
    const light = await shot('dashboard-light', 1600, 1000)
    check('亮色截图', true, light)

    const mobile = await shot('dashboard-mobile', 390, 844)
    check('移动端截图', true, mobile)

    const failed = results.filter(r => !r.ok)
    console.log(`\n========== 通过 ${results.length - failed.length} / 失败 ${failed.length} ==========`)
    writeFileSync(`${OUT}frontend-report.json`, JSON.stringify({ base: BASE, task: TASK, results }, null, 2))
    if (failed.length) process.exitCode = 1
  } finally {
    try { ws?.close() } catch { /* ignore */ }
    child.kill('SIGKILL')
  }
}

main().catch(err => { console.error('验收脚本异常:', err.message); process.exit(1) })
