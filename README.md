# XDU-SCE_OS-Experiment_2021

西安电子科技大学网络与信息安全学院 2019 级操作系统实验报告 by arttnba3

> 什么是 98 分的含金量啊（
> ![image.png](https://i.loli.net/2021/10/27/mdQSbY5A8HiytzD.png)
> ~~什么，你问为什么没拿 100 分，可能是因为太多人抄了被老师发现了~~

**md 文件只是帮助大家更方便地阅读，真正要交上去的还得是用老师给的那个实验报告模板**

## Environment

Ubuntu 20.04

## Exp-1 Syscall Basis

大概是要手写一个 `cp` 程序，然后用 `strace` 查看过程中用到的系统调用

## Exp-2 Muitiprocess Programming - Linux Shell

手写一个 `shell` ，代码可以直接参见 [a3shell](https://github.com/arttnba3/a3shell) ，详细说明可以参见 [Linux Kernel 简易食用指南 - 编写自己的shell - arttnba3's blog](https://arttnba3.cn/2021/02/21/NOTE-0X02-LINUX-KERNEL-PWN-PART-I/#七、编写自己的shell) 

目前而言 `1.0` 版只需要 glibc， `1.1` 版需要 `lreadline` 库，但是支持 tab 补全，打算有时间优化一哈（下次一定）

## Exp-3 Multithreaded Sorting Application

两个数组用两个线程排一哈，第三个线程给他合起来，~~纯苦力活有手就能写~~

## Exp-4 Multithreaded Programming with Semaphore

多线程编程，用信号量解决`生产者-消费者`问题，~~还是纯苦力活有手就能写~~

## Exp-5 File System

感受一下 Linux 下的文件链接机制，~~没啥意义~~

## Exp-6 Research of Linux

大概是做一个 Linux 系统相关的研究报告，综述型或者针对某个方面进行研究

笔者这里写的对 CVE-2016-5195 的研究（其实是在 [吃老本](https://arttnba3.cn/2021/04/08/CVE-0X00-CVE-2016-5195/) 呜呜呜）

## Exp-7 Compile the Linux Kernel

大概是编译 Linux 内核然后给笔者的小破机子换上去，~~然后自己写一个114514号系统调用每次调用都会在内核缓冲区输出哼哼啊啊啊啊啊啊啊啊啊啊~~

参见[Linux Kernel 简易食用指南 - arttnba3's blog](https://arttnba3.cn/2021/02/21/NOTE-0X02-LINUX-KERNEL-PWN-PART-I/) 
