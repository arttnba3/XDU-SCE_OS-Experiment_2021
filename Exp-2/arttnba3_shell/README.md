# a3shell

a simple bash-like shell programme prepared for my OS lesson in advance.

more infomation at [my blog](https://arttnba3.cn/2021/02/21/NOTE-0X02-LINUX-KERNEL-PWN-PART-I/#%e4%b8%83%e3%80%81%e7%bc%96%e5%86%99%e8%87%aa%e5%b7%b1%e7%9a%84shell)

## current progress

18%, only a simple appearance, which can execute some simple progress

## appearance

The one on the left is ```a3shell```, and the other one on the right is ```bash```

![image.png](https://i.loli.net/2021/03/05/dVrnBjGHvlz9Ioe.png)

## version

### 1.0

the basic version, only glibc is neededs

### 1.1

[The GNU Readline Library](https://tiswww.case.edu/php/chet/readline/rltop.html) need to be installed:

```shell
$ sudo apt-get install libreadline-gplv2-dev
$ sudo apt-get install libreadline6-dev
```

the new version has imported the Readline Library to provide the automatic code completion function and some other optimization