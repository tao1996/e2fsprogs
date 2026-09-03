#!/usr/bin/env bash
#
# extract_extfs.sh — 递归提取 ext2/ext3/ext4 文件系统镜像到本地目录
#
# 基于 e2fsprogs 工具集：
#   - debugfs 的 rdump 命令基于 libext2fs 递归遍历目录树并转储文件；
#   - dumpe2fs 用于校验镜像是否为合法的 ext 文件系统。
#
set -euo pipefail

usage() {
    cat <<'EOF'
用法:
    extract_extfs.sh [选项] <镜像文件> <目标目录>
    extract_extfs.sh -s <路径> <镜像文件> <目标目录>

描述:
    递归地将 ext2/ext3/ext4 文件系统镜像的内容提取到本地目标目录。

选项:
    -s, --src <路径>   仅提取镜像内的指定目录(默认提取根目录 /)
    -h, --help         显示本帮助并退出

示例:
    extract_extfs.sh disk.img ./extracted
    extract_extfs.sh -s /etc disk.img ./etc_backup

说明:
    - 默认提取根目录 / 的全部内容到目标目录。
    - 使用 -s 时，源目录以自身名称作为子目录落在目标目录下
      (例如 -s /etc 会得到 <目标目录>/etc/...)。
    - 需要 root 权限方可完整保留文件属主；普通用户也可提取可读内容。
    - 符号链接、空目录会被正确重建。
EOF
}

# —— 依赖检查 ——
DEBUGFS="$(command -v debugfs || true)"
DUMPE2FS="$(command -v dumpe2fs || true)"
if [[ -z "${DEBUGFS}" || -z "${DUMPE2FS}" ]]; then
    echo "错误: 未找到 debugfs 或 dumpe2fs，请先安装 e2fsprogs。" >&2
    exit 1
fi

# —— 参数解析 ——
SRC="/"
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--src)
            [[ $# -ge 2 ]] || { echo "错误: $1 需要参数" >&2; exit 2; }
            SRC="$2"
            shift 2
            ;;
        --src=*)
            SRC="${1#*=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "错误: 未知选项 $1" >&2
            exit 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ ${#ARGS[@]} -ne 2 ]]; then
    usage >&2
    exit 2
fi
IMG="${ARGS[0]}"
DEST="${ARGS[1]}"

# —— 校验镜像 ——
if [[ ! -f "${IMG}" ]]; then
    echo "错误: 镜像文件不存在: ${IMG}" >&2
    exit 1
fi
if ! "${DUMPE2FS}" -h "${IMG}" >/dev/null 2>&1; then
    echo "错误: 不是有效的 ext2/ext3/ext4 文件系统镜像: ${IMG}" >&2
    exit 1
fi

mkdir -p "${DEST}"

# —— 递归提取 ——
# 将镜像路径解析为绝对路径(后续会 cd 到目标目录)。
IMG_ABS="$(cd "$(dirname "${IMG}")" && pwd)/$(basename "${IMG}")"

if ! pushd "${DEST}" >/dev/null; then
    echo "错误: 无法进入目标目录: ${DEST}" >&2
    exit 1
fi

echo "正在递归提取 ${IMG} (${SRC}) -> ${DEST} ..."

# rdump: 递归转储；"." 即当前目录(DEST)。debugfs 对部分错误返回码为 0，
# 因此通过捕获 stderr 中的错误关键字判定失败。
errlog="$(mktemp)"
if ! "${DEBUGFS}" -R "rdump ${SRC} ." "${IMG_ABS}" >/dev/null 2>"${errlog}"; then
    cat "${errlog}" >&2
    rm -f "${errlog}"
    popd >/dev/null
    exit 1
fi
if grep -qiE 'file not found|no such file or directory|ext2_lookup|while statting|couldn[^ ]*t find' "${errlog}"; then
    cat "${errlog}" >&2
    rm -f "${errlog}"
    popd >/dev/null
    exit 1
fi
rm -f "${errlog}"
popd >/dev/null

echo "完成: 已提取 ${IMG} (${SRC}) -> ${DEST}"