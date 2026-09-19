FROM python:3.11-slim

# 环境变量：Python 不生成 .pyc、输出不缓冲、固定服务端口与数据库路径
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_PORT=8080 \
    AUDIT_DB_PATH=/data/audit.db

WORKDIR /app

# 先装依赖，利用镜像层缓存
COPY requirements.txt .
RUN pip install -r requirements.txt

# 复制应用代码与启动脚本
COPY app ./app
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh \
    && mkdir -p /data

EXPOSE 8080

# 启动时初始化数据库（建表 + 演示数据），再启动服务
ENTRYPOINT ["./entrypoint.sh"]
