/*
 * extract_extfs.c — 基于 libext2fs 递归提取 ext2/ext3/ext4 镜像，
 *                   并记录 fs_config 与 file_contexts(SELinux)。
 *
 * 参考：
 *   - e2fsprogs debugfs 的 rdump 实现 (debugfs/dump.c)
 *   - erofs-tools extract.erofs 的 fs_config / file_contexts 生成逻辑
 *     (ErofsWriter.cpp / ErofsNode.cpp / ErofsNodeHelper.cpp)
 *
 * 用法:
 *     extract_extfs <镜像文件> <输出目录>
 *
 * 输出结构(与 extract.erofs 一致):
 *     <输出目录>/<镜像名>/...            递归提取出的文件树
 *     <输出目录>/config/<镜像名>_fs_config        fs_config 记录
 *     <输出目录>/config/<镜像名>_file_contexts    SELinux 上下文记录
 *
 * fs_config     每行: <path> <uid> <gid> <mode(4位八进制)> [ capabilities=0xX]
 * file_contexts 每行: <转义后的path> <转义后的SELinux标签>
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <et/com_err.h>
#include <ext2fs/ext2fs.h>

/* —— security.capability 解析(与 linux/capability.h 一致, 自包含) —— */
typedef struct {
	__le32 magic_etc;
	struct {
		__le32 permitted;
		__le32 inheritable;
	} data[2];
} vfs_cap_data_t;

#define VFS_CAP_REVISION_MASK	0xFF000000
#define VFS_CAP_REVISION_1	0x01000000
#define VFS_CAP_REVISION_2	0x02000000
#define VFS_CAP_REVISION_3	0x03000000
#define XATTR_CAPS_SZ_1		(4 * (1 + 2 * 1))	/* 12 */
#define XATTR_CAPS_SZ_2		(4 * (1 + 2 * 2))	/* 20 */
#define XATTR_CAPS_SZ_3		(4 * (2 + 2 * 2))	/* 24 */

#define XATTR_NAME_SELINUX	"security.selinux"
#define XATTR_NAME_CAPABILITY	"security.capability"

/* —— 全局上下文 —— */
static ext2_filsys g_fs = NULL;
static const char *g_outdir = NULL;	/* 提取根目录, 以 '/' 结尾 */
static FILE *g_fs_config_fp = NULL;
static FILE *g_file_contexts_fp = NULL;

static void usage(const char *prog)
{
	fprintf(stderr,
		"用法: %s <镜像文件> <输出目录>\n"
		"\n"
		"递归提取 ext2/ext3/ext4 镜像中的所有文件, 并记录 fs_config 与\n"
		"SELinux 上下文(file_contexts)。\n"
		"\n"
		"输出:\n"
		"    <输出目录>/<镜像名>/...                     提取出的文件树\n"
		"    <输出目录>/config/<镜像名>_fs_config        fs_config\n"
		"    <输出目录>/config/<镜像名>_file_contexts    SELinux 上下文\n",
		prog);
}

/*
 * 转义 file_contexts 中的正则特殊字符(与 extract.erofs 的
 * handleSpecialSymbols 一致): 对 . + [ ] * 进行反斜杠转义。
 */
static void escape_special_symbols(char *dst, size_t dst_size, const char *src)
{
	size_t n = 0;

	while (*src && n + 2 < dst_size) {
		char c = *src;
		if (c == '.' || c == '+' || c == '[' || c == ']' || c == '*')
			dst[n++] = '\\';
		dst[n++] = c;
		src++;
	}
	dst[n] = '\0';
}

/* 将镜像内路径(src, 以 '/' 开头)拼接为本地提取路径写入 dst。 */
static void make_out_path(char *dst, size_t dst_size, const char *path)
{
	if (path[0] == '/' && path[1] == '\0')
		snprintf(dst, dst_size, "%s", g_outdir);
	else
		snprintf(dst, dst_size, "%s%s", g_outdir, path + 1);
}

/* 递归建目录(类似 mkdir -p)。 */
static int mkdir_p(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	size_t len = strlen(path);
	size_t i;

	if (len == 0 || len >= sizeof(tmp))
		return -1;
	snprintf(tmp, sizeof(tmp), "%s", path);

	/* 去掉末尾连续的 '/' */
	while (len > 1 && tmp[len - 1] == '/')
		tmp[--len] = '\0';

	for (i = 1; i < len; i++) {
		if (tmp[i] != '/')
			continue;
		tmp[i] = '\0';
		if (mkdir(tmp, mode) != 0 && errno != EEXIST)
			return -1;
		tmp[i] = '/';
	}
	if (mkdir(tmp, mode) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

/* 读取指定 xattr 值; 成功返回 ext2fs 分配的内存(需 ext2fs_free_mem), 失败返回 NULL。 */
static char *read_xattr(ext2_ino_t ino, const char *name, size_t *out_len)
{
	struct ext2_xattr_handle *h = NULL;
	void *value = NULL;
	size_t value_len = 0;
	errcode_t err;

	*out_len = 0;

	err = ext2fs_xattrs_open(g_fs, ino, &h);
	if (err)
		return NULL;
	err = ext2fs_xattrs_read(h);
	if (err)
		goto out;
	err = ext2fs_xattr_get(h, name, &value, &value_len);
	if (err)
		goto out;
	*out_len = value_len;

out:
	ext2fs_xattrs_close(&h);
	return value;
}

/*
 * 根据 security.capability 的 vfs_cap_data 计算 capabilities,
 * 结果写入 out(如 " capabilities=0x1F")。无反 capability 时写入空串。
 * 与 extract.erofs ErofsNodeHelper::initSecurityContext 逻辑一致。
 */
static void build_capability_suffix(const char *value, size_t value_len,
				    char *out, size_t out_size)
{
	const vfs_cap_data_t *data;
	uint32_t magic;
	uint64_t capabilities = 0;

	out[0] = '\0';
	if (!value || value_len == 0)
		return;

	data = (const vfs_cap_data_t *)value;
	magic = ext2fs_le32_to_cpu(data->magic_etc);

	switch (magic & VFS_CAP_REVISION_MASK) {
	case VFS_CAP_REVISION_1:
		if (value_len != XATTR_CAPS_SZ_1)
			return;
		capabilities = ext2fs_le32_to_cpu(data->data[0].permitted);
		break;
	case VFS_CAP_REVISION_2:
	case VFS_CAP_REVISION_3:
		if (value_len != XATTR_CAPS_SZ_2 && value_len != XATTR_CAPS_SZ_3)
			return;
		capabilities =
			ext2fs_le32_to_cpu(data->data[0].permitted) |
			((uint64_t)ext2fs_le32_to_cpu(data->data[1].permitted) << 32);
		break;
	default:
		return;
	}

	if (capabilities)
		snprintf(out, out_size, " capabilities=0x%llX",
			 (unsigned long long)capabilities);
}

/*
 * 记录不区分文件类型的 fs_config 与 file_contexts。
 * 每个 inode 都会调用到这里。
 */
static void record_fs_config_and_selinux(ext2_ino_t ino, const char *path)
{
	struct ext2_inode inode;
	uint32_t uid, gid, mode;
	char cap_suffix[64];
	char *cap_value = NULL;
	char *se_value = NULL;
	size_t cap_len = 0, se_len = 0;

	if (ext2fs_read_inode(g_fs, ino, &inode)) {
		com_err("record_fs_config", 0, "while reading inode for %s", path);
		return;
	}

	uid = inode_uid(inode);
	gid = inode_gid(inode);
	mode = inode.i_mode & 0777;

	cap_value = read_xattr(ino, XATTR_NAME_CAPABILITY, &cap_len);
	build_capability_suffix(cap_value, cap_len, cap_suffix, sizeof(cap_suffix));

	/* fs_config: <path> <uid> <gid> <mode-octal>[ capabilities=0xX] */
	fprintf(g_fs_config_fp, "%s %u %u %04o%s\n",
		path, uid, gid, mode, cap_suffix);

	/* file_contexts: <转义path> <转义label> (仅当存在 selinux 标签)
	 * xattr 值不含 NUL 结尾, 需先补 NUL 再按字符串处理。 */
	se_value = read_xattr(ino, XATTR_NAME_SELINUX, &se_len);
	if (se_value && se_len > 0) {
		char escaped_path[PATH_MAX * 2];
		char *label = malloc(se_len + 1);
		char *escaped_label = malloc(se_len * 2 + 1);

		if (label && escaped_label) {
			memcpy(label, se_value, se_len);
			label[se_len] = '\0';
			escape_special_symbols(escaped_path, sizeof(escaped_path), path);
			escape_special_symbols(escaped_label, se_len * 2 + 1, label);
			fprintf(g_file_contexts_fp, "%s %s\n", escaped_path, escaped_label);
		}
		free(label);
		free(escaped_label);
	}

	if (cap_value)
		ext2fs_free_mem(&cap_value);
	if (se_value)
		ext2fs_free_mem(&se_value);
}

/* 提取普通文件(参考 debugfs dump_file)。 */
static int extract_file(ext2_ino_t ino, const char *out_path)
{
	errcode_t retval;
	ext2_file_t e2_file = NULL;
	char *buf = NULL;
	unsigned int got;
	unsigned int blocksize = g_fs->blocksize;
	int fd;
	int rc = -1;

	fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
	if (fd < 0) {
		com_err("extract_file", errno, "while opening %s", out_path);
		return -1;
	}

	retval = ext2fs_file_open(g_fs, ino, 0, &e2_file);
	if (retval) {
		com_err("extract_file", retval, "while opening inode for %s", out_path);
		close(fd);
		return -1;
	}

	retval = ext2fs_get_mem(blocksize, &buf);
	if (retval) {
		com_err("extract_file", retval, "while allocating memory");
		goto out;
	}

	for (;;) {
		retval = ext2fs_file_read(e2_file, buf, blocksize, &got);
		if (retval) {
			com_err("extract_file", retval, "while reading %s", out_path);
			goto out;
		}
		if (got == 0)
			break;
		if (write(fd, buf, got) != (ssize_t)got) {
			com_err("extract_file", errno, "while writing %s", out_path);
			goto out;
		}
	}
	rc = 0;

out:
	if (buf)
		ext2fs_free_mem(&buf);
	if (e2_file)
		ext2fs_file_close(e2_file);
	close(fd);
	return rc;
}

/* 提取符号链接(支持 fast/slow symlink)。 */
static int extract_symlink(ext2_ino_t ino, const char *out_path)
{
	struct ext2_inode inode;
	char *target = NULL;
	size_t len;
	int rc = -1;

	if (ext2fs_read_inode(g_fs, ino, &inode)) {
		com_err("extract_symlink", 0, "while reading inode for %s", out_path);
		return -1;
	}

	len = (size_t)inode.i_size;
	target = malloc(len + 1);
	if (!target)
		return -1;

	if (ext2fs_is_fast_symlink(&inode)) {
		memcpy(target, (char *)inode.i_block, len);
		target[len] = '\0';
	} else {
		ext2_file_t e2_file = NULL;
		unsigned int got = 0;
		errcode_t retval;

		retval = ext2fs_file_open(g_fs, ino, 0, &e2_file);
		if (retval) {
			com_err("extract_symlink", retval,
				"while opening inode for %s", out_path);
			goto out;
		}
		retval = ext2fs_file_read(e2_file, target, len, &got);
		if (retval) {
			com_err("extract_symlink", retval,
				"while reading target of %s", out_path);
			ext2fs_file_close(e2_file);
			goto out;
		}
		target[got] = '\0';
		ext2fs_file_close(e2_file);
	}

	if (symlink(target, out_path) < 0) {
		com_err("extract_symlink", errno, "while creating %s", out_path);
		goto out;
	}
	rc = 0;

out:
	free(target);
	return rc;
}

/* 提取设备节点 / FIFO(需要 root 权限, 失败时尽力而为)。 */
static int extract_special(const struct ext2_inode *inode, const char *out_path)
{
	dev_t rdev = 0;
	mode_t mode = inode->i_mode & 07777;

	if (LINUX_S_ISCHR(inode->i_mode) || LINUX_S_ISBLK(inode->i_mode)) {
		rdev = inode->i_block[0]
			? (dev_t)inode->i_block[0]
			: (dev_t)inode->i_block[1];
	}

	if (mknod(out_path, mode, rdev) < 0) {
		com_err("extract_special", errno, "while creating %s", out_path);
		return -1;
	}
	return 0;
}

/* 设置权限 / 属主 / 时间(参考 extract.erofs set_attributes)。 */
static void set_attributes(const struct ext2_inode *inode, const char *out_path)
{
	struct timespec ts[2];
	int is_lnk = LINUX_S_ISLNK(inode->i_mode);

	ts[0].tv_sec = (time_t)inode->i_atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = (time_t)inode->i_mtime;
	ts[1].tv_nsec = 0;
	utimensat(AT_FDCWD, out_path, ts, is_lnk ? AT_SYMLINK_NOFOLLOW : 0);

	if (!is_lnk)
		chmod(out_path, inode->i_mode & 07777);

	if (geteuid() == 0) {
		if (lchown(out_path, inode_uid(*inode), inode_gid(*inode)) < 0)
			com_err("set_attributes", errno, "while changing ownership of %s", out_path);
	}
}

/* 目录遍历回调: 对子目录项递归处理。 */
struct dir_iter_ctx {
	const char *path;	/* 当前目录在镜像内的路径, 以 '/' 开头 */
};

static int process_node(ext2_ino_t ino, struct ext2_inode *inode, const char *path);

static int dump_dirent(struct ext2_dir_entry *dirent, int offset,
		       int blocksize, char *buf, void *priv_data)
{
	struct dir_iter_ctx *ctx = priv_data;
	ext2_ino_t child_ino;
	struct ext2_inode child_inode;
	int name_len;
	char name[EXT2_NAME_LEN + 1];
	char child_path[PATH_MAX];

	(void)offset;
	(void)blocksize;
	(void)buf;

	child_ino = dirent->inode;
	name_len = ext2fs_dirent_name_len(dirent);

	/* 跳过无效项与 . / .. */
	if (child_ino == 0 || name_len == 0)
		return 0;
	if (name_len == 1 && dirent->name[0] == '.')
		return 0;
	if (name_len == 2 && dirent->name[0] == '.' && dirent->name[1] == '.')
		return 0;

	if (name_len > (int)sizeof(name) - 1)
		name_len = sizeof(name) - 1;
	memcpy(name, dirent->name, name_len);
	name[name_len] = '\0';

	/* 拼接镜像内完整路径 */
	if (strcmp(ctx->path, "/") == 0)
		snprintf(child_path, sizeof(child_path), "/%s", name);
	else
		snprintf(child_path, sizeof(child_path), "%s/%s", ctx->path, name);

	if (ext2fs_read_inode(g_fs, child_ino, &child_inode)) {
		com_err("dump_dirent", 0, "while reading inode for %s", child_path);
		return 0;
	}

	process_node(child_ino, &child_inode, child_path);
	return 0;
}

/* 处理单个 inode(记录配置 + 提取)。 */
static int process_node(ext2_ino_t ino, struct ext2_inode *inode, const char *path)
{
	char out_path[PATH_MAX];
	int is_root = (path[0] == '/' && path[1] == '\0');

	make_out_path(out_path, sizeof(out_path), path);

	/* 1) 记录 fs_config 与 SELinux 上下文 */
	record_fs_config_and_selinux(ino, path);

	if (LINUX_S_ISREG(inode->i_mode)) {
		if (extract_file(ino, out_path) == 0)
			set_attributes(inode, out_path);
		return 0;
	}

	if (LINUX_S_ISDIR(inode->i_mode)) {
		struct dir_iter_ctx ctx;

		if (!is_root && mkdir(out_path, 0700) != 0 && errno != EEXIST) {
			com_err("process_node", errno, "while making directory %s", out_path);
			return -1;
		}

		ctx.path = path;
		ext2fs_dir_iterate(g_fs, ino, 0, NULL, dump_dirent, &ctx);

		if (!is_root)
			set_attributes(inode, out_path);
		return 0;
	}

	if (LINUX_S_ISLNK(inode->i_mode)) {
		if (extract_symlink(ino, out_path) == 0)
			set_attributes(inode, out_path);
		return 0;
	}

	if (LINUX_S_ISCHR(inode->i_mode) || LINUX_S_ISBLK(inode->i_mode) ||
	    LINUX_S_ISFIFO(inode->i_mode) || LINUX_S_ISSOCK(inode->i_mode)) {
		if (extract_special(inode, out_path) == 0)
			set_attributes(inode, out_path);
		return 0;
	}

	/* 其它类型(如 socket)暂不处理 */
	return 0;
}

int main(int argc, char *argv[])
{
	errcode_t retval;
	int flags;
	const char *image;
	const char *outdir;
	char base[NAME_MAX + 1];
	char *extract_root = NULL;
	char *config_dir = NULL;
	char *outdir_buf = NULL;
	char *fs_config_path = NULL;
	char *file_contexts_path = NULL;
	struct ext2_inode root_inode;
	int rc = 1;

	if (argc != 3) {
		usage(argv[0]);
		return 2;
	}
	image = argv[1];
	outdir = argv[2];

	/* 镜像名前缀(去掉首个 '.' 及其后的扩展名), 与 extract.erofs 一致。 */
	{
		const char *p = strrchr(image, '/');
		const char *b = p ? p + 1 : image;
		size_t i = 0;
		while (b[i] && b[i] != '.' && i < sizeof(base) - 1) {
			base[i] = b[i];
			i++;
		}
		base[i] = '\0';
	}

	/* 输出目录: <输出目录>/<镜像名>/ 用于提取; <输出目录>/config/ 用于记录。 */
	if (asprintf(&extract_root, "%s/%s", outdir, base) < 0 ||
	    asprintf(&config_dir, "%s/config", outdir) < 0) {
		com_err("extract_extfs", errno, "while building output paths");
		goto done;
	}

	if (mkdir_p(extract_root, 0755) != 0) {
		com_err("extract_extfs", errno, "while creating %s", extract_root);
		goto done;
	}
	if (mkdir_p(config_dir, 0755) != 0) {
		com_err("extract_extfs", errno, "while creating %s", config_dir);
		goto done;
	}

	if (asprintf(&outdir_buf, "%s/", extract_root) < 0) {
		com_err("extract_extfs", errno, "while building extraction root");
		goto done;
	}
	g_outdir = outdir_buf;

	if (asprintf(&fs_config_path, "%s/%s_fs_config", config_dir, base) < 0 ||
	    asprintf(&file_contexts_path, "%s/%s_file_contexts", config_dir, base) < 0) {
		com_err("extract_extfs", errno, "while building config paths");
		goto done;
	}

	g_fs_config_fp = fopen(fs_config_path, "w");
	if (!g_fs_config_fp) {
		com_err("extract_extfs", errno, "while opening %s", fs_config_path);
		goto done;
	}
	g_file_contexts_fp = fopen(file_contexts_path, "w");
	if (!g_file_contexts_fp) {
		com_err("extract_extfs", errno, "while opening %s", file_contexts_path);
		goto done;
	}

	/* 打开镜像(以只读方式, 支持 ext4 64bit 等特性)。 */
	flags = EXT2_FLAG_SOFTSUPP_FEATURES | EXT2_FLAG_64BITS;
	retval = ext2fs_open(image, flags, 0, 0, unix_io_manager, &g_fs);
	if (retval) {
		com_err("extract_extfs", retval, "while opening %s", image);
		goto done;
	}

	if (ext2fs_read_inode(g_fs, EXT2_ROOT_INO, &root_inode)) {
		com_err("extract_extfs", 0, "while reading root inode");
		goto done;
	}

	fprintf(stderr, "正在递归提取 %s -> %s ...\n", image, extract_root);

	process_node(EXT2_ROOT_INO, &root_inode, "/");

	fprintf(stderr, "完成: 文件树 -> %s\n", extract_root);
	fprintf(stderr, "      fs_config -> %s\n", fs_config_path);
	fprintf(stderr, "      file_contexts -> %s\n", file_contexts_path);
	rc = 0;

done:
	if (g_fs)
		ext2fs_close(g_fs);
	if (g_fs_config_fp)
		fclose(g_fs_config_fp);
	if (g_file_contexts_fp)
		fclose(g_file_contexts_fp);
	free(extract_root);
	free(config_dir);
	free(outdir_buf);
	free(fs_config_path);
	free(file_contexts_path);
	return rc;
}