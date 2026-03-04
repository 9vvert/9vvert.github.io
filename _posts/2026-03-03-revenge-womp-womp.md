---
title: ehaxCTF - revenge-womp-womp
categories: [ctf2026, ehaxCTF]
tags: [pwn, heap, large-bin, unlink, ORW]
---

比赛期间这一题根本没看，赛后学习了@`j0xnd03`大佬的脚本，涉及到了large bin attack, unsafe-unlink等以前还没有学过的技术，期间看了很多blog恶补相关知识，一晚上+一上午才终于理清了攻击思路。第一次见到这么长的利用链，真让人兴奋！

### 0x01 - 语义分析
程序实现了一个简易虚拟机：
```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  void *s; // [rsp+8h] [rbp-18h]

  sub_401262(a1, a2, a3);
  while ( 1 )
  {
    puts("Pls input the opcode");
    s = malloc(0x2000u);
    if ( !s )
      break;
    memset(s, 0, 0x2000u);
    if ( read(0, s, 0x500u) <= 0 )
    {
      free(s);
      _exit(0);
    }
    dispatch((__int64)s);
    free(s);
  }
  _exit(0);
}
```
核心是dispatch函数：
```c
unsigned __int64 __fastcall dispatch(__int64 a1)
{
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  while ( 1 )
  {
    switch ( *(_BYTE *)a1 & 0xF )
    {
      case 1:
        alloc(a1);
        a1 += 4;
        puts("Malloc Done");
        break;
      case 2:
        delete(a1);
        a1 += 2;
        puts("Del Done");
        break;
      case 3:
        show(a1);
        a1 += 2;
        puts("Show Done");
        break;
      case 4:
        edit(a1);
        a1 += *(unsigned __int16 *)(a1 + 2) + 4;
        puts("Edit Done");
        break;
      case 5:
        return v3 - __readfsqword(0x28u);
      case 6:
        leak();
        ++a1;
        break;
      default:
        puts("Invalid opcode");
        ++a1;
        break;
    }
  }
}
```
其中alloc函数中只允许large bin范围的chunk:
```c
unsigned __int64 __fastcall alloc(__int64 pc)
{
  unsigned __int8 idx; // [rsp+15h] [rbp-1Bh]
  unsigned __int16 alloc_size; // [rsp+16h] [rbp-1Ah]
  unsigned __int64 v4; // [rsp+18h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  idx = *(_BYTE *)(pc + 1);
  alloc_size = *(_WORD *)(pc + 2);
  if ( alloc_size <= 0x40Fu || alloc_size > 0x500u || idx > 0x10u )
  {
    puts("ERROR");
    _exit(0);
  }
  ptr_array[idx] = calloc(1u, alloc_size);
  if ( !ptr_array[idx] )
  {
    puts("ERROR");
    _exit(0);
  }
  size_array[idx] = alloc_size;
  return v4 - __readfsqword(0x28u);
}
```
而在delete中没有在ptr_array中删掉free后的表项，导致UAF.

LLM跑的opcode总结：
```markdown
  ### Opcode 1: Allocate ( sub_401310 ,  0x401310 )                           
                                                                              
  Input format:                                                               
                                                                              
  •  byte 0 : opcode low nibble = 1                                           
  •  byte 1 :  idx                                                            
  •  bytes 2..3 :  size  ( uint16 )                                           
                                                                              
  Checks:                                                                     
                                                                              
  • Reject if  size <= 0x40F  or  size > 0x500                                
  • Reject if  idx > 0x10                                                     
  • Allocates  calloc(1, size)  and stores in globals                         
                                                                              
  ### Opcode 2: Delete ( sub_401410 ,  0x401410 )                             
                                                                              
  Input format:                                                               
                                                                              
  •  byte 0 : opcode low nibble = 2                                           
  •  byte 1 :  idx                                                            
                                                                              
  Checks:                                                                     
                                                                              
  • Reject if  idx > 0x10  or pointer is null                                 
  • Calls  free(qword_404180[idx])                                            
                                                                              
  ### Opcode 3: Show ( sub_4014AB ,  0x4014ab )                               
                                                                              
  Input format:                                                               
                                                                              
  •  byte 0 : opcode low nibble = 3                                           
  •  byte 1 :  idx                                                            
                                                                              
  Checks:                                                                     
                                                                              
  • Reject if  idx > 0x10  or pointer is null                                 
  • Calls  puts(qword_404180[idx])                                            
                                                                              
  ### Opcode 4: Edit ( sub_401546 ,  0x401546 )                               
                                                                              
  Input format:                                                               
                                                                              
  •  byte 0 : opcode low nibble = 4                                           
  •  byte 1 :  idx                                                            
  •  bytes 2..3 :  len  ( uint16 )                                            
  •  bytes 4.. : payload                                                      
                                                                              
  Checks:                                                                     
                                                                              
  • Reject if  idx > 0x10  or pointer is null                                 
  • Clamp: if  len > chunk_size[idx] , then  len = chunk_size[idx]            
  •  memcpy(chunk_ptr[idx], payload, len)                                     
                                                                              
  ### Opcode 6: Diagnostic ( sub_40163B ,  0x40163b )                         
                                                                              
  Prints:                                                                     
                                                                              
  •  printf("diag:%#lx\n", __readfsqword(0) + 48);                            
                                                                              
  This leaks an address derived from thread-local storage base ( FS ), useful 
  as an info leak primitive.                      
```

### 0x02 - 学习large bin attack
这一题存在的UAF能够轻易导致double free, 但可惜alloc中强制我们使用large-bin，所以不能使用简单的fastbin-double-free，tcache-poisoning等攻击方法。

参考自Axura's Blog以及CTF wiki:
> https://4xura.com/binex/heap/large-bin-attack/
https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/large-bin-attack/

pmalloc中有63个large bin:
```
Group-------Amount--------Offset
1-----------32------------64(0x40)
2-----------16------------512(0x200)
3-----------8-------------4096(0x1000)
4-----------4-------------32768(0x8000)
5-----------2-------------262144(0x40000)
6-----------1-------------unlimited
```
比如第一组的offset为0x40, 意味着这一组的每个bin覆盖了0x40的范围，依次为0x400~0x440, 0x440~0x480, ...等。
比如0x400~0x440的这个bin, 其大致结构是这样的：
![](/assets/ctf/2026/revenge_womp_womp_large_bin.png)

bin-header是一个伪chunk； 而其它的chunk会按照下列规则组织：
1. 相同大小的chunk通过fd/bk构成的双向链表构成一个局部链
2. 而这个局部链的header, 会通过fd_nextsize/bk_nextsize参与构成bin-header所在的链

large bin是有序排列的，从bin-header开始，fd方向，size逐渐减小.

然后是一些相关的规则：
1. 大于fastbin & tcache范围的chunk在第一次被free后，会放进unsorted bin中
2. 当malloc一个块的时候，如果tcache/fastbin中没有符合要求的块，smallbin/largebin也为空的话，会将unsorted bin中的块放到相应的smallbin/largebin中，然后再在其中寻找。优先找完美匹配，如果没有再进行分割。而分割后的块，又一次放进unsorted bin中。（感觉malloc分配的时候有很多细节，日后需要再深入学习）
3. 当新的块进入largebin时，会根据自己的大小位置插入(操作类似unlink，可以实现任意位置的写入，只不过写入的内容是一个chunk ptr, 所以单独存在时，杀伤力并不是很大，往往作为辅助手段，比如绕过unlink的检查)。从2.30开始，增加了新的fd_nextsize/bk_nextsize检查；不过有一个偷鸡的方法：上面的检查发生在链表遍历的过程中，这个过程是为了寻找新块的合适位置，满足largebin的有序性。如果新chunk比当前largebin的任何一个chunk都小（直接通过bin-header->bk找到最小项），会直接将其插入到末尾，从而绕过检查。

重要的源码:（其中bck/fwd一般代表目标chunk实际上应该插入位置的前/后一个chunk指针；victim一般代表“当前正在处理的块”）
```c
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
{
    bck = victim->bk;
    if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
        || __builtin_expect (chunksize_nomask (victim)
                   > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
    size = chunksize (victim);
 
    /*
      If a small request, try to use last remainder if it is the
      only chunk in unsorted bin.  This helps promote locality for
      runs of consecutive small requests. This is the only
      exception to best-fit, and applies only when there is
      no exact fit for a small chunk.
    */
 
    if (in_smallbin_range (nb) &&
        bck == unsorted_chunks (av) &&
        victim == av->last_remainder &&
        (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
    {
        /* split and reattach remainder */
        remainder_size = size - nb;
        remainder = chunk_at_offset (victim, nb);
        unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
        av->last_remainder = remainder;
        remainder->bk = remainder->fd = unsorted_chunks (av);
        if (!in_smallbin_range (remainder_size))
        {
            remainder->fd_nextsize = NULL;
            remainder->bk_nextsize = NULL;
        }
 
        set_head (victim, nb | PREV_INUSE |
                  (av != &main_arena ? NON_MAIN_ARENA : 0));
        set_head (remainder, remainder_size | PREV_INUSE);
        set_foot (remainder, remainder_size);
 
        check_malloced_chunk (av, victim, nb);
        void *p = chunk2mem (victim);
        alloc_perturb (p, bytes);
        return p;
    }
 
    /* remove from unsorted list */
    unsorted_chunks (av)->bk = bck;
    bck->fd = unsorted_chunks (av);
 
    /* Take now instead of binning if exact fit */
 
    if (size == nb)
    {
         set_inuse_bit_at_offset (victim, size);
         if (av != &main_arena)
             set_non_main_arena (victim);
         check_malloced_chunk (av, victim, nb);
         void *p = chunk2mem (victim);
         alloc_perturb (p, bytes);
         return p;
    }
 
    /* place chunk in bin */
    if (in_smallbin_range (size))
    {
        victim_index = smallbin_index (size);
        bck = bin_at (av, victim_index);
        fwd = bck->fd;
    }
    else
    {
        victim_index = largebin_index (size);
        bck = bin_at (av, victim_index);
        fwd = bck->fd;
        // 初始的时候：bck == bin-header,  fwd == bin-header -> fd == largebin的首个块，也就是最大的chunk
 
        /* maintain large bins in sorted order */
        if (fwd != bck)     // fwd != bck代表largebin除了header外至少有一个有效chunk
        {
             /* Or with inuse bit to speed comparisons */
             size |= PREV_INUSE;
             /* if smaller than smallest, bypass loop below */
             assert (chunk_main_arena (bck->bk));     
             if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))   // bck->bk == bin-header->bk == 最后一个块，也就是最小的块
             {
                  // 这种情况下，可以确定插入到链表末尾，所以重新规划fwd和bck. (目标插入位置是末端的话，fwd应该是bin-header, 所以设置fwd = bck; 另一侧同理
                 fwd = bck;
                 bck = bck->bk;
                 // 现在fwd->fd就是最大的chunk, 下面的两行用来维护nextsize链
                 victim->fd_nextsize = fwd->fd;
                 victim->bk_nextsize = fwd->fd->bk_nextsize;
                 // 这是第一个漏洞点
                 // 我们控制插入前largebin中最小chunk的bk字段；经过上面的nextsize变换后，victim->bk_nextsize就是我们控制的块
                 // 如果我们事先将其bk_nextsize字段为target_addr - 32,
                 // 那么victim->bk_nextsize->fd_nextsize = *(target_addr - 32 + 32) = victim
                 fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
              }
              else
              {
                  assert (chunk_main_arena (fwd));
                  while ((unsigned long) size < chunksize_nomask (fwd))
                  {
                      fwd = fwd->fd_nextsize;
                      assert (chunk_main_arena (fwd));
                  }
 
                  if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                  else
                  {
                      victim->fd_nextsize = fwd;
                      victim->bk_nextsize = fwd->bk_nextsize;
                      fwd->bk_nextsize = victim;
                      victim->bk_nextsize->fd_nextsize = victim;
                  }
                  bck = fwd->bk;
              }
          }
          else
              victim->fd_nextsize = victim->bk_nextsize = victim;
    }
 
 
 
    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    // 第二个漏洞点：
    // 我们控制插入前largebin中最小chunk的bk字段；在插入的时候，会更新fwd和bck，现在bck就是我们控制的chunk
    // 如果我们事先将bck->fd字段写成target_addr - 16,
    // 那么bck->fd = *(target_addr - 16 + 16) = victim
    fwd->bk = victim;
    bck->fd = victim;
 
#define MAX_ITERS       10000
    if (++iters >= MAX_ITERS)
        break;
}
```
我们如果能够控制large bin中最小块的bk/bk_nextsize，就能实现对任意位置写入victim指针。


### 0x03 unlink
单纯的largebin attack只能实现任意位置写入一个堆指针，但是并不能写入任意数据。接下来要借助unlink来实现任意位置读写，核心就是让我们能够把任意地址当成一个合法chunk进行操作。其中一个思路是：malloc到任意地址，比如fastbin-double-free中；但是目前我们没有直接堆溢出，并不容易实现。

而unlink技术, 我们就能往任意位置写入8字节数据。到这里可利用性已经很高了，但是我们还可以更进一步，用unlink作为跳板，升级到“任意位置读写任意字节”，只需要修改ptr_array中的某个指针即可，这一题没有PIE,也省去了泄露pie_base的麻烦.

在unlink中有两类检查：
```c
// 大小
next_chunk(p)->prev_chunksize == p->chunksize
// 链表正确性检查
p->fd->bk == p
p->bk->fd == p
```
在没有直接堆溢出的时候，我们可以借助largebin attack来辅助.

我们可以控制的部分是p->fd和p->bk (chunksize目前不能修改)，可以从“结果”出发，先满足在target_addr写入8字节数据，然后再设法满足check.
unlink的时候会执行：
```
p->fd->bk = p->bk
p->bk->fd = p->fd
```
目前有两种选择：
1. p->fd = target_addr - 0x18, p->bk = data
2. p->bk - target_addr - 0x10, p->fd = data

然后就是满足链表正确性的检查，可以设法让p->fd->bk == p->bk->fd指向同一个位置，然后通过largebin attack将其修改成p(victim)的地址，一次性满足两个条件。
但是这也带来了一个副作用：p-fd->bk = p->bk和p->bk->fd = p->fd相当于对同一个地址赋值两次，所以只有最后一次的计算有效。那么我们只有一种选择了：
```
p->bk = target_addr - 0x10  // 注意这里需要p->bk->fd == target_addr
p->fd = data
```
进一步推断：要让p->fd->bk == p->bk->fd，也即 `p->fd + 0x18 == p->bk + 0x10`, 那么`p->fd = target - 0x18`
```
p->fd = target_addr - 0x18
p->bk = target_addr - 0x10
```
(结论竟然非常对称)
最后实现的效果是：*(target_addr) = target - 0x18, 也即将目标地址的数据写成目标地址 - 0x18
假设ptr_array中每隔8字节存储一个堆指针, 那么我们把第四个ptr当成target_addr, 经过unlink攻击后，第四个槽存储的值不再是一个堆指针，而是指向第一个槽（在这一题中，位于.data段上）.

注意：malloc返回的地址指向的是chunk的usr_data字段，而不是chunk的起始地址。所以当ptr_array中指向slot1后，直接写入8个字节即可控制slot1的指针，进一步对chunk1操作即可实现任意位置读写！

### 0x04 [TODO]

### 0x05 完整脚本
```python
#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF("./pwn", checksec=False)
libc = ELF("./handout/libc.so.6", checksec=False)
ld = ELF("./handout/ld.so", checksec=False)

HOST = args.HOST or "127.0.0.1"
PORT = int(args.PORT or 1337)


def start():
    if args.GDB:
        return gdb.debug(
            [exe.path],
            gdbscript="""
            set pagination off
            continue
            """,
        )
    if args.REMOTE:
        return remote(HOST, PORT)
    return process([exe.path])


def op_alloc(idx: int, size: int) -> bytes:
    return p8(1) + p8(idx) + p16(size)


def op_free(idx: int) -> bytes:
    return p8(2) + p8(idx)


def op_show(idx: int) -> bytes:
    return p8(3) + p8(idx)


def op_edit(idx: int, data: bytes, n: int = None) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    if n is None:
        n = len(data)
    return p8(4) + p8(idx) + p16(n) + data


def op_exit() -> bytes:
    return p8(5)


def op_diag() -> bytes:
    return p8(6)


class Womp:
    def __init__(self, io):
        self.io = io

    def send_ops(self, ops: bytes, end: bool = True):
        self.io.recvuntil(b"Pls input the opcode")
        payload = ops + (op_exit() if end else b"")
        assert len(payload) <= 0x500, "payload must be <= 0x500"
        self.io.send(payload)

    def alloc(self, idx: int, size: int):
        self.send_ops(op_alloc(idx, size))
        self.io.recvuntil(b"Malloc Done")

    def free(self, idx: int):
        self.send_ops(op_free(idx))
        self.io.recvuntil(b"Del Done")

    def show(self, idx: int) -> bytes:
        self.send_ops(op_show(idx))
        out = self.io.recvuntil(b"Show Done", drop=True)
        return out

    def edit(self, idx: int, data: bytes, n: int = None):
        self.send_ops(op_edit(idx, data, n=n))
        self.io.recvuntil(b"Edit Done")

    def diag(self) -> int:
        self.send_ops(op_diag())
        self.io.recvuntil(b"diag:")
        line = self.io.recvline().strip()
        return int(line, 16)

    def transact(self, ops: list[bytes]) -> bytes:
        self.send_ops(b"".join(ops))
        return self.io.recvuntil(b"\n", timeout=0.1)


def main():
    io = start()
    w = Womp(io)

    # Example usage:
    w.alloc(0, 0x420)
    w.edit(0, b"AAAA\n")
    leak = w.show(0)
    log.info(f"show(0) => {leak!r}")

    diag = w.diag()
    log.info(f"diag leak = {diag:#x}")

    io.interactive()


if __name__ == "__main__":
    main()
```