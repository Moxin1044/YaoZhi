/* 遥知 · 前端逻辑
   流程：上传日志 → 轮询任务进度 → 拉取结果 → 渲染指标与图表
   图表统一用 ECharts；主题跟随 data-theme 切换。 */

(function () {
  "use strict";

  var charts = {};
  var currentTaskId = null;
  var currentResult = null;

  /* ------------------------------------------------------------ 工具函数 */

  function $(id) { return document.getElementById(id); }

  function bytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + " B";
    var units = ["KB", "MB", "GB", "TB"], v = n;
    for (var i = 0; i < units.length; i++) {
      v /= 1024;
      if (v < 1024) return (v < 10 ? v.toFixed(2) : v.toFixed(1)) + " " + units[i];
    }
    return v.toFixed(1) + " PB";
  }

  function num(n) { return (Number(n) || 0).toLocaleString("zh-CN"); }

  function pct(n) { return (Number(n) || 0).toFixed(2) + "%"; }

  function escapeHtml(text) {
    return String(text == null ? "" : text).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function themeColors() {
    var dark = document.documentElement.getAttribute("data-theme") !== "light";
    return {
      text: dark ? "#e6edf7" : "#101c2e",
      muted: dark ? "#8ca0bd" : "#5b6b84",
      split: dark ? "rgba(148,163,184,0.16)" : "#e4e9f0",
      series: dark
        ? ["#22d3ee", "#a78bfa", "#34d399", "#fbbf24", "#f87171", "#60a5fa", "#f472b6"]
        : ["#0891b2", "#7c3aed", "#059669", "#d97706", "#dc2626", "#2563eb", "#db2777"]
    };
  }

  /* ------------------------------------------------------------ 图表基础 */

  function chart(id) {
    var el = $(id);
    if (!el || typeof echarts === "undefined") return null;
    if (!charts[id]) {
      charts[id] = echarts.init(el, null, { renderer: "canvas" });
    }
    return charts[id];
  }

  function baseOption(extra) {
    var c = themeColors();
    var option = {
      color: c.series,
      textStyle: { color: c.text, fontSize: 12 },
      grid: { left: 48, right: 22, top: 34, bottom: 40, containLabel: true },
      tooltip: { trigger: "axis", backgroundColor: "rgba(15,23,42,0.92)", borderWidth: 0, textStyle: { color: "#e6edf7", fontSize: 12 } },
      xAxis: { type: "category", axisLine: { lineStyle: { color: c.split } }, axisLabel: { color: c.muted } },
      yAxis: { type: "value", splitLine: { lineStyle: { color: c.split } }, axisLabel: { color: c.muted } }
    };
    return Object.assign(option, extra || {});
  }

  function disposeCharts() {
    Object.keys(charts).forEach(function (k) { charts[k].dispose(); delete charts[k]; });
  }

  /* ------------------------------------------------------------ 指标卡 */

  function renderMetrics(overview, parseStats, meta) {
    var items = [
      { label: "总请求数", value: num(overview.requests), sub: "QPS " + (overview.qps || 0), cls: "accent" },
      { label: "独立 IP (UV)", value: num(overview.uv), sub: "独立路径 " + num(overview.unique_urls) },
      { label: "页面浏览 (PV)", value: num(overview.pv), sub: "已排除静态资源" },
      { label: "总流量", value: bytes(overview.bandwidth), sub: "平均 " + bytes(overview.avg_size) + "/请求" },
      { label: "错误请求", value: num(overview.errors), sub: "错误率 " + pct(overview.error_rate), cls: overview.error_rate > 5 ? "danger" : "warn" },
      { label: "爬虫流量", value: pct(overview.bot_rate), sub: "真人 " + num(overview.human_requests), cls: "ok" },
      { label: "日志解析率", value: pct(parseStats.success_rate), sub: "解析 " + num(parseStats.parsed) + " / 失败 " + num(parseStats.failed), cls: parseStats.success_rate > 99 ? "ok" : "warn" },
      { label: "时间跨度", value: (overview.duration_hours || 0) + " h", sub: (meta && meta.file) ? meta.file : "" }
    ];
    $("metrics").innerHTML = items.map(function (it) {
      return '<div class="metric ' + (it.cls || "") + '">' +
        '<div class="label">' + escapeHtml(it.label) + "</div>" +
        '<div class="value">' + escapeHtml(it.value) + "</div>" +
        '<div class="sub">' + escapeHtml(it.sub || "") + "</div>" +
        "</div>";
    }).join("");
  }

  /* ------------------------------------------------------------ 各图表 */

  function renderTrend(timeseries) {
    var c = chart("chartTrend");
    if (!c) return;
    var points = (timeseries && timeseries.points) || [];
    var option = baseOption({
      legend: { top: 0, textStyle: { color: themeColors().muted } },
      tooltip: { trigger: "axis" },
      xAxis: { type: "category", boundaryGap: false, data: points.map(function (p) { return p.time; }),
        axisLine: { lineStyle: { color: themeColors().split } }, axisLabel: { color: themeColors().muted, hideOverlap: true } },
      yAxis: [{ type: "value", name: "请求", splitLine: { lineStyle: { color: themeColors().split } }, axisLabel: { color: themeColors().muted } },
              { type: "value", name: "UV", splitLine: { show: false }, axisLabel: { color: themeColors().muted } }],
      series: [
        { name: "请求数", type: "line", smooth: true, showSymbol: false, areaStyle: { opacity: 0.16 },
          data: points.map(function (p) { return p.requests; }) },
        { name: "PV", type: "line", smooth: true, showSymbol: false,
          data: points.map(function (p) { return p.pv; }) },
        { name: "独立 IP", type: "line", yAxisIndex: 1, smooth: true, showSymbol: false,
          data: points.map(function (p) { return p.uv; }) },
        { name: "错误数", type: "bar", barMaxWidth: 10, itemStyle: { color: "#f87171", opacity: 0.75 },
          data: points.map(function (p) { return p.errors; }) }
      ]
    });
    c.setOption(option, true);
  }

  function renderStatus(statusCodes) {
    var c = chart("chartStatus");
    if (!c) return;
    var items = (statusCodes.items || []).slice(0, 8).map(function (i) {
      return { name: String(i.code), value: i.count };
    });
    c.setOption(baseOption({
      tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
      legend: { bottom: 0, textStyle: { color: themeColors().muted }, type: "scroll" },
      grid: null,
      xAxis: null, yAxis: null,
      series: [{
        type: "pie", radius: ["48%", "72%"], center: ["50%", "45%"],
        itemStyle: { borderColor: "transparent", borderWidth: 2 },
        label: { color: themeColors().text, formatter: "{b}\n{d}%" },
        data: items
      }]
    }), true);
  }

  function renderDevice(clients) {
    var c = chart("chartDevice");
    if (!c) return;
    var data = ((clients && clients.devices) || []).map(function (d) { return { name: d.name, value: d.count }; });
    c.setOption(baseOption({
      tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
      legend: { bottom: 0, textStyle: { color: themeColors().muted } },
      grid: null, xAxis: null, yAxis: null,
      series: [{ type: "pie", radius: ["48%", "72%"], center: ["50%", "45%"],
        itemStyle: { borderColor: "transparent", borderWidth: 2 },
        label: { color: themeColors().text, formatter: "{b}\n{d}%" }, data: data }]
    }), true);
  }

  function renderUrls(topUrls) {
    var c = chart("chartUrls");
    if (!c) return;
    var items = (topUrls || []).slice(0, 10).reverse();
    c.setOption(baseOption({
      grid: { left: 10, right: 40, top: 16, bottom: 16, containLabel: true },
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      xAxis: { type: "value", splitLine: { lineStyle: { color: themeColors().split } }, axisLabel: { color: themeColors().muted } },
      yAxis: { type: "category", data: items.map(function (i) { return i.path; }),
        axisLine: { lineStyle: { color: themeColors().split } },
        axisLabel: { color: themeColors().muted, formatter: function (v) { return v.length > 26 ? v.slice(0, 25) + "…" : v; } } },
      series: [{ type: "bar", barMaxWidth: 14, itemStyle: { borderRadius: [0, 6, 6, 0] },
        label: { show: true, position: "right", color: themeColors().muted, fontSize: 11 },
        data: items.map(function (i) { return i.requests; }) }]
    }), true);
  }

  function renderBrowser(clients) {
    var c = chart("chartBrowser");
    if (!c) return;
    var browsers = (clients && clients.browsers) || [];
    var systems = (clients && clients.systems) || [];
    c.setOption(baseOption({
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      legend: { top: 0, textStyle: { color: themeColors().muted } },
      xAxis: { type: "category", data: browsers.map(function (b) { return b.name; }),
        axisLine: { lineStyle: { color: themeColors().split } },
        axisLabel: { color: themeColors().muted, interval: 0, rotate: 22, fontSize: 11 } },
      yAxis: { type: "value", splitLine: { lineStyle: { color: themeColors().split } }, axisLabel: { color: themeColors().muted } },
      series: [
        { name: "浏览器", type: "bar", barMaxWidth: 18, itemStyle: { borderRadius: [6, 6, 0, 0] },
          data: browsers.map(function (b) { return b.count; }) },
        { name: "操作系统", type: "bar", barMaxWidth: 18, itemStyle: { borderRadius: [6, 6, 0, 0] },
          data: systems.map(function (s) { return s.count; }) }
      ]
    }), true);
  }

  function renderMethod(methods) {
    var c = chart("chartMethod");
    if (!c) return;
    var data = (methods || []).map(function (m) { return { name: m.method, value: m.count }; });
    c.setOption(baseOption({
      tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
      legend: { bottom: 0, textStyle: { color: themeColors().muted } },
      grid: null, xAxis: null, yAxis: null,
      series: [{ type: "pie", radius: ["46%", "70%"], center: ["50%", "45%"],
        itemStyle: { borderColor: "transparent", borderWidth: 2 },
        label: { color: themeColors().text, formatter: "{b}\n{d}%" }, data: data }]
    }), true);
  }

  function renderReferer(referers) {
    var c = chart("chartReferer");
    if (!c) return;
    var items = ((referers && referers.items) || []).slice(0, 8);
    var labels = ["直接访问", "站内跳转"].concat(items.map(function (i) { return i.domain; }));
    var values = [referers.direct || 0, referers.internal || 0].concat(items.map(function (i) { return i.count; }));
    c.setOption(baseOption({
      grid: { left: 10, right: 24, top: 16, bottom: 16, containLabel: true },
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      xAxis: { type: "value", splitLine: { lineStyle: { color: themeColors().split } }, axisLabel: { color: themeColors().muted } },
      yAxis: { type: "category", data: labels.reverse(),
        axisLine: { lineStyle: { color: themeColors().split } },
        axisLabel: { color: themeColors().muted, formatter: function (v) { return v.length > 24 ? v.slice(0, 23) + "…" : v; } } },
      series: [{ type: "bar", barMaxWidth: 14, itemStyle: { borderRadius: [0, 6, 6, 0] },
        data: values.reverse() }]
    }), true);
  }

  function renderHeatmap(heatmap) {
    var c = chart("chartHeatmap");
    if (!c) return;
    var data = [];
    (heatmap.matrix || []).forEach(function (row, y) {
      row.forEach(function (v, x) { data.push([x, y, v]); });
    });
    c.setOption({
      tooltip: {
        position: "top",
        backgroundColor: "rgba(15,23,42,0.92)", borderWidth: 0, textStyle: { color: "#e6edf7", fontSize: 12 },
        formatter: function (p) { return heatmap.weekdays[p.value[1]] + " " + p.value[0] + ":00 · " + p.value[2] + " 次"; }
      },
      grid: { left: 56, right: 20, top: 16, bottom: 46 },
      xAxis: { type: "category", data: (heatmap.hours || []).map(function (h) { return h + ":00"; }),
        axisLine: { lineStyle: { color: themeColors().split } }, axisLabel: { color: themeColors().muted, fontSize: 10 } },
      yAxis: { type: "category", data: heatmap.weekdays || [],
        axisLine: { lineStyle: { color: themeColors().split } }, axisLabel: { color: themeColors().muted } },
      visualMap: { min: 0, max: Math.max(1, heatmap.max || 1), calculable: true, orient: "horizontal",
        left: "center", bottom: 4, textStyle: { color: themeColors().muted, fontSize: 11 },
        inRange: { color: themeColors().series.slice(0, 4).map(function (c1) { return c1; }) } },
      series: [{ type: "heatmap", data: data, itemStyle: { borderRadius: 3 },
        emphasis: { itemStyle: { borderColor: themeColors().text, borderWidth: 1 } } }]
    }, true);
  }

  /* ------------------------------------------------------------ 表格 */

  function renderIps(topIps) {
    var body = $("ipTable").querySelector("tbody");
    if (!topIps || !topIps.length) {
      body.innerHTML = '<tr><td colspan="9" class="empty">暂无数据</td></tr>';
      return;
    }
    body.innerHTML = topIps.map(function (ip) {
      var mark = ip.is_bot ? '<span class="tag bot">' + escapeHtml(ip.bot_name || "爬虫") + "</span>"
                           : '<span class="tag ok">真人</span>';
      return "<tr>" +
        '<td class="mono">' + escapeHtml(ip.ip) + "</td>" +
        "<td>" + escapeHtml(ip.location || "-") + "</td>" +
        '<td class="num">' + num(ip.requests) + "</td>" +
        '<td class="num">' + pct(ip.percent) + "</td>" +
        '<td class="num">' + bytes(ip.bandwidth) + "</td>" +
        "<td>" + escapeHtml(ip.browser || "-") + "</td>" +
        "<td>" + escapeHtml(ip.os || "-") + "</td>" +
        "<td>" + escapeHtml(ip.device || "-") + "</td>" +
        "<td>" + mark + "</td>" +
        "</tr>";
    }).join("");
  }

  function renderErrors(errors) {
    var body = $("errorTable").querySelector("tbody");
    var items = (errors && errors.by_url) || [];
    if (!items.length) {
      body.innerHTML = '<tr><td colspan="4" class="empty">没有错误请求</td></tr>';
      return;
    }
    body.innerHTML = items.slice(0, 15).map(function (e) {
      var codes = Object.keys(e.codes || {}).map(function (c) {
        return '<span class="tag danger">' + escapeHtml(c) + "×" + e.codes[c] + "</span>";
      }).join(" ");
      return "<tr>" +
        '<td class="mono">' + escapeHtml(e.path) + "</td>" +
        '<td class="num">' + num(e.count) + "</td>" +
        "<td>" + codes + "</td>" +
        '<td class="num">' + num(e.unique_ips) + "</td>" +
        "</tr>";
    }).join("");
  }

  function renderSuspicious(items) {
    var body = $("suspiciousTable").querySelector("tbody");
    if (!items || !items.length) {
      body.innerHTML = '<tr><td colspan="4" class="empty">未发现常见探测特征</td></tr>';
      return;
    }
    body.innerHTML = items.slice(0, 15).map(function (s) {
      var codes = Object.keys(s.status_codes || {}).map(function (c) {
        return '<span class="tag warn">' + escapeHtml(c) + "×" + s.status_codes[c] + "</span>";
      }).join(" ");
      return "<tr>" +
        '<td class="mono">' + escapeHtml(s.path) + "</td>" +
        '<td class="num">' + num(s.count) + "</td>" +
        '<td class="num">' + num(s.unique_ips) + "</td>" +
        "<td>" + codes + "</td>" +
        "</tr>";
    }).join("");
  }

  /* ------------------------------------------------------------ 结果渲染 */

  function renderResult(result) {
    if (!result || !result.overview) {
      $("uploadError").hidden = false;
      $("uploadError").textContent = "结果为空或格式不受支持";
      return;
    }
    currentResult = result;
    $("resultSection").hidden = false;
    $("resultMeta").textContent = "时间范围 " + result.overview.start_time + " ~ " + result.overview.end_time;

    renderMetrics(result.overview, result.parse_stats || {}, result.meta || {});
    renderTrend(result.timeseries);
    renderStatus(result.status_codes || {});
    renderDevice(result.clients || {});
    renderUrls(result.top_urls || []);
    renderBrowser(result.clients || {});
    renderMethod(result.methods || []);
    renderReferer(result.referers || {});
    renderHeatmap(result.heatmap || {});
    renderIps(result.top_ips || []);
    renderErrors(result.errors || {});
    renderSuspicious(result.suspicious || []);

    $("resultSection").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  /* ------------------------------------------------------------ 上传流程 */

  function setProgress(status, progress) {
    $("progressWrap").hidden = false;
    $("progressLabel").textContent = status || "分析中…";
    $("progressValue").textContent = (progress || 0) + "%";
    $("progressBar").style.width = (progress || 0) + "%";
  }

  function uploadFile(file) {
    if (!file) return;
    var err = $("uploadError");
    err.hidden = true;

    if (!/\.(log|txt)$/i.test(file.name)) {
      err.hidden = false;
      err.textContent = "仅支持 .log / .txt 文件";
      return;
    }

    var form = new FormData();
    form.append("file", file);
    setProgress("上传中…", 2);

    fetch("/", { method: "POST", body: form })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.task_id || data.task_id === 0) {
          throw new Error("服务端拒绝上传（可能已关闭上传开关）");
        }
        currentTaskId = data.task_id;
        pollTask(data.task_id);
      })
      .catch(function (e) {
        err.hidden = false;
        err.textContent = "上传失败：" + e.message;
        $("progressWrap").hidden = true;
      });
  }

  function pollTask(taskId) {
    var timer = setInterval(function () {
      fetch("/task_status/" + encodeURIComponent(taskId))
        .then(function (r) { return r.json(); })
        .then(function (s) {
          setProgress(s.status, s.progress || 0);
          if (s.status === "完成") {
            clearInterval(timer);
            setProgress("完成", 100);
            loadResult(taskId);
            setTimeout(function () { $("progressWrap").hidden = true; }, 1200);
          } else if (s.status === "失败") {
            clearInterval(timer);
            $("uploadError").hidden = false;
            $("uploadError").textContent = "分析失败，请检查日志格式";
            $("progressWrap").hidden = true;
          }
        })
        .catch(function () { clearInterval(timer); });
    }, 900);
  }

  function loadResult(taskId) {
    fetch("/task_results/" + encodeURIComponent(taskId))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.success) throw new Error(data.message || "结果读取失败");
        renderResult(data.results);
      })
      .catch(function (e) {
        $("uploadError").hidden = false;
        $("uploadError").textContent = "结果读取失败：" + e.message;
      });
  }

  /* ------------------------------------------------------------ 任务历史 */

  function loadHistory() {
    fetch("/api/v1/tasks?page=1&limit=20")
      .then(function (r) { return r.json(); })
      .then(function (resp) {
        var items = (resp.data && resp.data.items) || [];
        var body = $("historyTable").querySelector("tbody");
        if (!items.length) {
          body.innerHTML = '<tr><td colspan="7" class="empty">暂无任务</td></tr>';
          return;
        }
        body.innerHTML = items.map(function (t) {
          var s = t.summary || {};
          return "<tr>" +
            '<td class="mono">' + escapeHtml(String(t.task_id).slice(0, 12)) + "</td>" +
            "<td>" + escapeHtml(t.status || "-") + "</td>" +
            '<td class="num">' + num(s.requests) + "</td>" +
            '<td class="num">' + num(s.uv) + "</td>" +
            '<td class="num">' + pct(s.error_rate) + "</td>" +
            "<td>" + escapeHtml(String(t.timestamp || "").slice(0, 19)) + "</td>" +
            '<td><button class="btn ghost small" data-task="' + escapeHtml(t.task_id) + '">查看</button></td>' +
            "</tr>";
        }).join("");
        body.querySelectorAll("button[data-task]").forEach(function (btn) {
          btn.addEventListener("click", function () { loadResult(this.getAttribute("data-task")); });
        });
      })
      .catch(function () { /* 历史加载失败不阻塞主流程 */ });
  }

  /* ------------------------------------------------------------ 导出 */

  function download(filename, content, type) {
    var blob = new Blob([content], { type: type || "application/json;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }

  /* ------------------------------------------------------------ 初始化 */

  function initTheme() {
    var saved = localStorage.getItem("yaozhi-theme") || "dark";
    document.documentElement.setAttribute("data-theme", saved);
    $("themeBtn").addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("yaozhi-theme", next);
      disposeCharts();
      if (currentResult) renderResult(currentResult);
    });
  }

  function initUpload() {
    var dz = $("dropzone"), input = $("fileInput");
    dz.addEventListener("click", function () { input.click(); });
    dz.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
    });
    input.addEventListener("change", function () { uploadFile(input.files[0]); });
    ["dragenter", "dragover"].forEach(function (evt) {
      dz.addEventListener(evt, function (e) { e.preventDefault(); dz.classList.add("dragover"); });
    });
    ["dragleave", "drop"].forEach(function (evt) {
      dz.addEventListener(evt, function (e) { e.preventDefault(); dz.classList.remove("dragover"); });
    });
    dz.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files.length) uploadFile(e.dataTransfer.files[0]);
    });
  }

  function initHistory() {
    $("historyBtn").addEventListener("click", function () {
      var card = $("historyCard");
      card.hidden = !card.hidden;
      if (!card.hidden) loadHistory();
    });
    $("historyClose").addEventListener("click", function () { $("historyCard").hidden = true; });
  }

  function initExport() {
    $("exportJson").addEventListener("click", function () {
      if (!currentResult) return;
      download("yaozhi-" + (currentTaskId || "result") + ".json", JSON.stringify(currentResult, null, 2));
    });
    $("exportCsv").addEventListener("click", function () {
      if (!currentTaskId) return;
      window.location = "/api/v1/tasks/" + encodeURIComponent(currentTaskId) + "/export?format=csv";
    });
  }

  function initInterval() {
    var seg = $("intervalSeg");
    seg.addEventListener("click", function (e) {
      var btn = e.target.closest("button");
      if (!btn) return;
      seg.querySelectorAll("button").forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");
      if (!currentResult || !currentTaskId) return;
      var interval = btn.getAttribute("data-interval");
      fetch("/api/v1/tasks/" + encodeURIComponent(currentTaskId) + "/timeseries?interval=" + interval)
        .then(function (r) { return r.json(); })
        .then(function (resp) {
          if (resp.data && resp.data.points && resp.data.points.length) renderTrend(resp.data);
        })
        .catch(function () { /* 静默失败，保留原图 */ });
    });
  }

  function initResize() {
    var timer = null;
    window.addEventListener("resize", function () {
      clearTimeout(timer);
      timer = setTimeout(function () {
        Object.keys(charts).forEach(function (k) { charts[k].resize(); });
      }, 160);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    initUpload();
    initHistory();
    initExport();
    initInterval();
    initResize();
  });

  // 暴露少量内部方法，便于自动化测试与页面调试
  window.__yaozhi = {
    loadResult: loadResult,
    renderResult: renderResult,
    uploadFile: uploadFile,
    version: "2.0.0"
  };
})();
