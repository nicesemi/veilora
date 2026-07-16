#!/bin/bash
# VEILORA 本地一键安装脚本
# 双击运行或在终端执行: bash setup.sh

set -e
REPO="https://github.com/nicesemi/veilora.git"
DIR="$HOME/veilora-local"

echo "========================================"
echo "  VEILORA 本地环境一键部署"
echo "========================================"
echo ""

# 检查 git
if ! command -v git &>/dev/null; then
    echo "[1/4] 安装 Git..."
    xcode-select --install 2>/dev/null || true
    echo "请先完成 Git 安装后重新运行此脚本"
    exit 1
fi

# 检查 python3
if ! command -v python3 &>/dev/null; then
    echo "错误：需要 Python 3，请先安装"
    exit 1
fi

# Clone 或更新
if [ -d "$DIR/.git" ]; then
    echo "[1/4] 更新已有仓库..."
    cd "$DIR"
    git pull origin main
else
    echo "[1/4] 克隆项目到 $DIR ..."
    rm -rf "$DIR"
    git clone "$REPO" "$DIR"
    cd "$DIR"
fi

echo "[2/4] 安装 Python 依赖..."
pip3 install -r requirements.txt

echo "[3/4] 启动本地服务器..."
echo ""
echo "========================================"
echo "  服务即将在浏览器中打开"
echo "  关闭此窗口即可停止服务"
echo "========================================"

# 打开浏览器
sleep 2
open "http://localhost:9000" 2>/dev/null || true

# 启动服务器
python3 server.py
