#!/bin/sh
# 容器入口：
#   1. 初始化 SQLite 数据库（建表、写入演示数据，已初始化则跳过）
#   2. 通过 uvicorn 在固定端口启动 FastAPI
set -e

APP_PORT="${APP_PORT:-8080}"

echo "[entrypoint] 初始化数据库 (${AUDIT_DB_PATH:-/data/audit.db}) ..."
python -c "from app.db import init_db; init_db(); print('[entrypoint] 数据库就绪')"

echo "[entrypoint] 启动服务，监听 0.0.0.0:${APP_PORT}"
exec uvicorn app.main:app --host 0.0.0.0 --port "${APP_PORT}"
