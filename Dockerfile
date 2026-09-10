# 遥知 · Web 日志分析 —— 生产镜像
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    YAOZHI_DB=/app/data/tasks.db \
    YAOZHI_UPLOAD_DIR=/app/data/uploads

WORKDIR /app

# 系统时区数据（日志时间解析依赖）
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata curl \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# 先装依赖，利用层缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 再拷贝源码
COPY . .

# 运行期目录
RUN mkdir -p /app/data/uploads

EXPOSE 7100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:7100/api/v1/health || exit 1

# 生产环境用 gunicorn；分析任务在请求线程内异步执行，故给足超时
CMD ["gunicorn", "-w", "4", "-k", "gthread", "--threads", "8", \
     "-b", "0.0.0.0:7100", "--timeout", "600", "--graceful-timeout", "30", \
     "--access-logfile", "-", "web.server:app"]
