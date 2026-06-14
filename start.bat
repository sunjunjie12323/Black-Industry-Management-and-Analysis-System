@echo off
chcp 65001 >nul 2>&1
title 威胁情报分析平台 - 启动器
echo.
echo  ╔══════════════════════════════════════════╗
echo  ║     威胁情报分析平台  一键启动           ║
echo  ╚══════════════════════════════════════════╝
echo.

:: Check Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo  [错误] 未检测到 Python，请先安装 Python 3.10+
    echo  下载地址: https://www.python.org/downloads/
    echo.
    echo  安装时请勾选 "Add Python to PATH"
    pause
    exit /b 1
)

:: Show Python version
for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo  [信息] 检测到 %%i

:: Set PYTHONPATH
set PYTHONPATH=%~dp0backend

:: Install dependencies
echo.
echo  [1/3] 安装依赖包...
pip install -r backend\requirements.txt -q 2>nul
if %errorlevel% neq 0 (
    echo  [提示] 依赖安装较慢，尝试使用国内镜像...
    pip install -r backend\requirements.txt -q -i https://pypi.tuna.tsinghua.edu.cn/simple 2>nul
    if %errorlevel% neq 0 (
        echo  [错误] 依赖安装失败，请检查网络连接
        pause
        exit /b 1
    )
)
echo  [完成] 依赖安装成功

:: Initialize database
echo.
echo  [2/3] 初始化数据库...
if not exist threat_intel.db (
    python -c "import asyncio; from app.db.database import init_db; asyncio.run(init_db())" 2>nul
    if exist threat_intel.db (
        echo  [完成] 数据库初始化成功
    ) else (
        echo  [提示] 数据库将在首次启动时自动创建
    )
) else (
    echo  [完成] 数据库已存在，跳过初始化
)

:: Start server
echo.
echo  [3/3] 启动服务...
echo.
echo  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo  访问地址: http://localhost:8000
echo  默认账号: admin
echo  默认密码: Admin@2024
echo  API文档:  http://localhost:8000/docs
echo  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo.
echo  按 Ctrl+C 停止服务
echo.

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
