# 实验七、**Linux内核编译**

> 参见[Linux Kernel 简易食用指南 - arttnba3's blog](https://arttnba3.cn/2021/02/21/NOTE-0X02-LINUX-KERNEL-PWN-PART-I/) 

## **一、实验题目**

下载、编译内核源代码

启动测试所编译出来的内核

## **二、相关原理与知识**

**（完成实验所用到的相关原理与知识）**

**Vmware 虚拟机的使用**

**Makefile 的使用**

**Linux 系统相关基础知识**

**Qemu 虚拟机的使用**

## **三、实验过程**

**（清晰展示实际操作过程，相关截图及解释）**

由于直接在（虚拟机）真机安装未经测试内核可能会发生预料之外的事情，笔者这里选择在编译好内核后先用 qemu 虚拟机进行测试，再替换掉Ubuntu 的原有内核

### Pre.安装依赖

环境是Ubuntu20.04

```shell
$ sudo apt-get update
$ sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils qemu flex libncurses5-dev fakeroot build-essential ncurses-dev xz-utils libssl-dev bc bison libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libelf-dev
```

### 一、获取内核镜像（bzImage）

#### I.获取内核源码

前往[Linux Kernel Archive](https://www.kernel.org/)下载对应版本的内核源码

笔者这里选用5.11这个版本的内核镜像

```shell
$ wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.11.tar.xz
```

#### II.配置编译选项

解压我们下载来的内核源码

```shell
$ tar -xvf linux-5.11.tar.xz
```

完成后进入文件夹内，执行如下命令开始配置编译选项

```shell
$ make menuconfig
```

进入如下配置界面

![image.png](https://i.loli.net/2021/02/21/YXVQhel4vjMHDSa.png)

保证勾选如下配置（默认都是勾选了的）：

- Kernel hacking ---> Kernel debugging
- Kernel hacking ---> Compile-time checks and compiler options ---> Compile the kernel with debug info
- Kernel hacking ---> Generic Kernel Debugging Instruments --> KGDB: kernel debugger
- kernel hacking ---> Compile the kernel with frame pointers 

一般来说不需要有什么改动，直接保存退出即可

#### III.开始编译

运行如下命令开始编译，生成内核镜像

```shell
$ make bzImage
```

> 可以使用make bzImage -j4加速编译
>
> 笔者机器比较烂，大概要等一顿饭的时间...
>
> 以及编译内核会比较需要空间，一定要保证磁盘剩余空间充足
>
> ##### 可能出现的错误
>
> 笔者在编译 4.4 版本的内核时出现了如下错误：
>
> ```shell
> cc1: error: code model kernel does not support PIC mode
> ```
>
> ```shell
> make[1]: *** No rule to make target 'debian/canonical-certs.pem', needed by 'certs/x509_certificate_list'.  Stop
> ```
>
> 这个时候只需要在Makefile文件中：
>
> - `KBUILD_CFLAGS` 的尾部添加选项 `-fno-pie`
> - `CC_USING_FENTRY` 项添加 `-fno-pic`
>
> 以及在 `.config` 文件中找到这一项，等于号后面的值改为 `""`
>
> ![image.png](https://i.loli.net/2021/04/08/kSBi5yhprCjqnfv.png)
>
> 最后又出现了一个错误...笔者实在忍不了了，换到Ubuntu 16进行编译...一遍过...
>
> 出现这种情况的原因主要是高版本的 gcc 更改了内部的一些相关机制，~~只需要切换回老版本gcc即可正常编译~~

完成之后会出现如下信息：

```shell
Kernel: arch/x86/boot/bzImage is ready  (#1)
```

##### vmlinux：原始内核文件

在当前目录下提取到```vmlinux```，为编译出来的原始内核文件

```shell
$ file vmlinux
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=f1fc85f87a5e6f3b5714dad93a8ac55fa7450e06, with debug_info, not stripped
```

##### bzImage：压缩内核镜像

在当前目录下的```arch/x86/boot/```目录下提取到```bzImage```，为压缩后的内核文件，适用于大内核

```shell
$ file arch/x86/boot/bzImage
arch/x86/boot/bzImage: Linux kernel x86 boot executable bzImage, version 5.11.0 (root@iZf3ye3at4zthpZ) #1 SMP Sun Feb 21 21:44:35 CST 2021, RO-rootFS, swap_dev 0xB, Normal VGA
```

> ###### zImage && bzImage
>
> zImage--是vmlinux经过gzip压缩后的文件。
> bzImage--bz表示“big zImage”，不是用bzip2压缩的，而是要偏移到一个位置，使用gzip压缩的。两者的不同之处在于，zImage解压缩内核到低端内存(第一个 640K)，bzImage解压缩内核到高端内存(1M以上)。如果内核比较小，那么采用zImage或bzImage都行，如果比较大应该用bzImage。 
>
> [https://blog.csdn.net/xiaotengyi2012/article/details/8582886](https://blog.csdn.net/xiaotengyi2012/article/details/8582886)

### 二、获取busybox

 BusyBox 是一个集成了三百多个最常用Linux命令和工具的软件，包含了例如ls、cat和echo等一些简单的工具

后续构建磁盘镜像我们需要用到busybox

#### 编译busybox

##### I.获取busybox源码

在[busybox.net](https://busybox.net/downloads/)下载自己想要的版本，笔者这里选用```busybox-1.33.0.tar.bz2```这个版本

```shell
$ wget https://busybox.net/downloads/busybox-1.33.0.tar.bz2
```

> 外网下载的速度可能会比较慢，可以在前面下载Linux源码的时候一起下载，也可以选择去国内的镜像站下载

解压

```shell
$ tar -jxvf busybox-1.33.0.tar.bz2
```

##### II.编译busybox源码

进入配置界面

```shell
$ make menuconfig
```

勾选Settings ---> Build static binary file (no shared lib)

>  若是不勾选则需要单独配置lib，比较麻烦

接下来就是编译了，速度会比编译内核快很多

```shell
$ make install
```

编译完成后会生成一个```_install```目录，接下来我们将会用它来构建我们的磁盘镜像

### 三、构建磁盘镜像

#### 建立文件系统

##### I.初始化文件系统

一些简单的初始化操作...

```shell
$ cd _install
$ mkdir -pv {bin,sbin,etc,proc,sys,home,lib64,lib/x86_64-linux-gnu,usr/{bin,sbin}}
$ touch etc/inittab
$ mkdir etc/init.d
$ touch etc/init.d/rcS
$ chmod +x ./etc/init.d/rcS
```

##### II.配置初始化脚本

首先配置```etc/inttab```，写入如下内容：

```shell
::sysinit:/etc/init.d/rcS
::askfirst:/bin/ash
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/swapoff -a
::shutdown:/bin/umount -a -r
::restart:/sbin/init
```

在上面的文件中指定了系统初始化脚本，因此接下来配置```etc/init.d/rcS```，写入如下内容：

```shell
#!/bin/sh
mount -t proc none /proc
mount -t sys none /sys
/bin/mount -n -t sysfs none /sys
/bin/mount -t ramfs none /dev
/sbin/mdev -s
```

主要是配置各种目录的挂载

也可以在根目录下创建```init```文件，写入如下内容：

```shell
#!/bin/sh
 
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev

exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
```

别忘了添加可执行权限：

```shell
$ chmod +x ./init
```

##### III.配置用户组

```shell
$ echo "root:x:0:0:root:/root:/bin/sh" > etc/passwd
$ echo "ctf:x:1000:1000:ctf:/home/ctf:/bin/sh" >> etc/passwd
$ echo "root:x:0:" > etc/group
$ echo "ctf:x:1000:" >> etc/group
$ echo "none /dev/pts devpts gid=5,mode=620 0 0" > etc/fstab
```

在这里建立了两个用户组```root```和```ctf```，以及两个用户```root```和```ctf```

##### IV.配置glibc库

将需要的动态链接库拷到相应位置即可

> 为了方便笔者这里就先不弄了，直接快进到下一步，以后有时间再补充（咕咕咕

#### 打包文件系统为镜像文件

使用如下命令打包文件系统

```shell
$ find . | cpio -o --format=newc > ../../rootfs.cpio
```

也可以这么写

```shell
$ find . | cpio -o -H newc > ../core.cpio
```

> 这里的位置是笔者随便选的，也可以将之放到自己喜欢的位置

#### 向文件系统中添加文件

若是我们后续需要向文件系统中补充一些其他的文件，可以选择在原先的```_install```文件夹中添加（不过这样的话若是配置多个文件系统则会变得很混乱），也可以解压文件系统镜像后添加文件再重新进行打包

##### I.解压磁盘镜像

```shell
$ cpio -idv < ./rootfs.cpio
```

该命令会将磁盘镜像中的所有文件解压到当前目录下

##### II.重打包磁盘镜像

和打包磁盘镜像的命令一样

```shell
$ find . | cpio -o --format=newc > ../new_rootfs.cpio
```

### 四、使用qemu运行内核

终于到了最激动人心的时候了：**我们即将要将这个Linux内核跑起来——用我们自己配置的文件系统与内核**

安全起见，我们并不直接在真机上运行这个内核，而是使用qemu在虚拟机里运行

#### 配置启动脚本

首先将先前的```bzImage```和```rootfs.cpio```放到同一个目录下

接下来编写启动脚本

```shell
$ touch boot.sh
```

写入如下内容：

```shell
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd  ./rootfs.cpio \
    -monitor /dev/null \
    -append "root=/dev/ram rdinit=/sbin/init console=ttyS0 oops=panic panic=1 loglevel=3 quiet nokaslr" \
    -cpu kvm64,+smep \
    -smp cores=2,threads=1 \
    -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
    -nographic \
    -s
```

部分参数说明如下：

- ```-m```：虚拟机内存大小
- ```-kernel```：内存镜像路径
- ```-initrd```：磁盘镜像路径
- ```-append```：附加参数选项
  - ```nokalsr```：关闭内核地址随机化，方便我们进行调试
  - ```rdinit```：指定初始启动进程，```/sbin/init```进程会默认以```/etc/init.d/rcS```作为启动脚本
  - ```loglevel=3 ``` & ```quiet```：不输出log
  - ```console=ttyS0```：指定终端为```/dev/ttyS0```，这样一启动就能进入终端界面
- ```-monitor```：将监视器重定向到主机设备```/dev/null```，这里重定向至null主要是防止CTF中被人给偷了qemu拿flag
- ```-cpu```：设置CPU安全选项，在这里开启了smep保护
- ```-s```：相当于```-gdb tcp::1234```的简写（也可以直接这么写），后续我们可以通过gdb连接本地端口进行调试

运行```boot.sh```，成功启动\~撒花\~🌸🌸🌸

![image.png](https://i.loli.net/2021/02/22/Aj9sYfLCrgZFVxI.png)

### 五、使用 qemu + gdb 调试Linux内核

#### 载入内核符号表

直接使用 gdb 载入之前在源码根目录下编译出来的未压缩内核镜像 vmlinux 即可

```shell
$ sudo gdb vmlinux
```

#### remote连接

我们启动时已经将内核映射到了本地的1234端口，只需要gdb连接上就行

```shell
pwndbg> set architecture i386:x86-64
pwndbg> target remote localhost:1234
```

> 笔者的gdb使用了```pwndbg```这个插件

![image.png](https://i.loli.net/2021/04/13/Uuxeshm3rTyXV8D.png)

源码 + 符号 + 堆栈 一目了然（截屏没法截全...

#### 寻找gadget

用ROPgadget或者ropper都行，笔者比较喜欢使用ROPgadget

```shell
$ ROPgadget --binary ./vmlinux > gadget.txt
```

一般出来大概有个几十MB

在CTF中有的kernel pwn题目仅给出压缩后镜像```bzImage```，此时我们可以使用如下脚本进行解压（来自[github](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux)）：

```shell
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# ----------------------------------------------------------------------

check_vmlinux()
{
	# Use readelf to check if it's a valid ELF
	# TODO: find a better to way to check that it's really vmlinux
	#       and not just an elf
	readelf -h $1 > /dev/null 2>&1 || return 1

	cat $1
	exit 0
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	for	pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
	do
		pos=${pos%%:*}
		tail -c+$pos "$img" | $3 > $tmp 2> /dev/null
		check_vmlinux $tmp
	done
}

# Check invocation:
me=${0##*/}
img=$1
if	[ $# -ne 1 -o ! -s "$img" ]
then
	echo "Usage: $me <kernel-image>" >&2
	exit 2
fi

# Prepare temp files:
tmp=$(mktemp /tmp/vmlinux-XXX)
trap "rm -f $tmp" 0

# That didn't work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
try_decompress '\002!L\030'   xxx   'lz4 -d'
try_decompress '(\265/\375'   xxx   unzstd

# Finally check for uncompressed images or objects:
check_vmlinux $img

# Bail out:
echo "$me: Cannot find vmlinux." >&2
```

用法如下：

```shell
$ ./extract-vmlinux ./bzImage > vmlinux
```

### 六、替换内核

好像一切都没有问题了，我们来把我们的新内核换到我们的主机上吧！

我们原有的机子的内核版本为 `5.8.0`

![image.png](https://i.loli.net/2021/05/08/JcYL8UQ7gnubORZ.png)

在编译好内核后，我们在之前的源码目录下继续执行如下指令：

```shell
$ sudo make modules
$ sudo make modules_install
$ sudo make install
$ sudo update-initramfs -c -k 5.11.0
$ sudo update-grub
$ sudo apt-get install linux-source
```

这里的 `5.11.0` 应为你自己的新内核版本号

需要注意的是**在执行命令之前我们应当预留足够的空间**

>  会比你预想中的可能还要再大一些![image.png](https://i.loli.net/2021/05/08/fqdbRMhuKCrIozk.png)

之后输入 `reboot` 命令重启即可

## **四、实验结果与分析**

在本次实验中，笔者成功地下载了 Linux 内核源码并完成编译的工作，同时还完成了编译内核模块与安装新内核的工作

重新进入系统，我们可以看到我们的内核版本已经被替换为 `5.11.0`

![image.png](https://i.loli.net/2021/05/08/TmgAvs1VnJuYHcS.png)

## **五、问题总结**

**唯一遇到的问题是编译内核模块到一半时提示空间不足，只好先关闭虚拟机，进行磁盘拓展后再重新启动，拓展好磁盘后再继续进行编译。**