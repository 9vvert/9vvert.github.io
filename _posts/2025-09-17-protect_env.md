---
title: protect_env
categories: [ctf2025, FortID]
tags: [pwn, system]
---


```c
// gcc -o chall chall.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rot13(char *s) {
  while (*s != 0) {
    *s += 13;
    s++;
  }
}

int main(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  char command[64];
  char name[64];

  while (1) {
    printf("> ");
    scanf("%63s %63s", command, name);
    if (!strcmp(command, "protect")) {
      char *val = getenv(name);
      if (val) {
        rot13(val);
        printf("Protected %s\n", name);
      } else {
        printf("No such environment variable\n");
      }
    } else if (!strcmp(command, "print")) {
      if (!strcmp(name, "FLAG")) {
        printf("Access denied\n");
      } else {
        char *val = getenv(name);
        if (val) {
          printf("%s=%s\n", name, val);
        } else {
          printf("No such environment variable\n");
        }
      }
    } else {
      printf("Unknown command\n");
      break ;
    }
  } 
  return 0;
}
```
flag存在于环境变量 `FLAG`中，但程序会对变量名进行过滤

> 想法1：能否通过其他环境变量来泄漏其内容？

> 想法2：尝试能否绕过FLAG


> 从条件入手，rot13函数能够提供什么？
当多次执行rot13函数后，字符串的某些位置可能会变成0,从而导致长度变化。但是这点微不足道的变化并不足以支撑起侧信道攻击


##### 尝试了解环境变量的存储结构
查阅资料后知道环境变量的存储是 "name=val"的形式，那么getenv函数应该就是通过 `=`符号来分割的。

最近在搞url解析歧义的课题，其中一个经典的畸形URL就是类似于`http://abc@@xyz` 这样，出现多个关键字符的时候，划分就有了歧义。
再看看这一题，给的是很老的libc.2.27,或许这些老旧的库函数划分也存在漏洞呢？

我们可以确定flag是以`FortID`开头的，执行19次rot13函数后第一个字符就会变成`=`，然后尝试读取`FLAG=`变量，果然输出了一串信息！解密即可获得flag
