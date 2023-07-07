# pwnable_tw

Started from 2022/08/26

This is a dirary of the amazing trip with pwnable-tw.

## start

Solved 08/26/2022

A very simple binary to get start, print out welcome message and read in user input. 

[EXP](./start/exp_start.py)

## orw

Solved 08/26/2022

As the description said "Only open read write syscall are allowed to use." Just write a 32-bit shellcode to read out the flag. 

[EXP](./orw/exp_orw.py)

## netatalk (CVE-2018-1160)

**TODO**

## calc

Solved 2022/08/26

A calculator challenge. The structure is quite similar to [win32-Calculator](https://thomasonzhao.cn/2022/01/07/win32-Calculator/) which I did earlier this year, but the difference is: I used to just to reverse it and attach an debugger to modify the value, now I have to exploit it. 

The main problem lies in the calculation part of the program. It determines the index of the closest operator (`+, -, *, /, %`) and then call `eval` function to calculate the result. But users are allowed not to put the first operand and it results arbitrary read/write. If user input the expression like `+100`, the arbitrary read happened on the `result[100]`. Same for arbitrary write. 

`eval`:

```c
void __cdecl eval(int *result, char operator)
{
  if ( operator == '+' )
  {
    result[*result - 1] += result[*result];
  }
  else if ( operator > '+' )
  {
    if ( operator == '-' )
    {
      result[*result - 1] -= result[*result];
    }
    else if ( operator == '/' )
    {
      result[*result - 1] /= result[*result];
    }
  }
  else if ( operator == '*' )
  {
    result[*result - 1] *= result[*result];
  }
  --*result;
}
```

So now with arbitrary read/write, we are able to construct the ROP chain. However, the gadgets only allows you use syscall once (no `ret` after any gadgets of `int 0x80`), so I decide to use a syscall already existed in the file to read in the string for a shell. 

[EXP](./calc/exp_calc.py)

## 3x17

Solved 2022/08/31

This is a static linked program without any symboles. Base on the interaction, it seems provide us an arbitrary write privilege, with the length of `0x18`. Every other mitigations are applied except for PIE/ASLR (checksec didn't realize the canary is on). 

So it's probably about doing some ROP stuff to hijack the control flow. But there is no buffer overflow through the reads. After some search, I found this: https://ctf-wiki.org/executable/elf/structure/code-sections/. It is said that the code in `.fini` & `.fini_array` part will be executed to quit the program properly. Tipically, `.fini` section store instructions and `.fini_array` section store the pointers to execute. From the reverse engineering, we can found that `.fini_array` section is at `0x4B40F0`, and luckily, we have writable permission. 

```gdb
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00000000400000 0x00000000401000 0x00000000000000 r-- ~/3x17/3x17
0x00000000401000 0x0000000048f000 0x00000000001000 r-x ~/3x17/3x17
0x0000000048f000 0x000000004b3000 0x0000000008f000 r-- ~/3x17/3x17
0x000000004b4000 0x000000004ba000 0x000000000b3000 rw- ~/3x17/3x17
0x000000004ba000 0x000000004bb000 0x00000000000000 rw-
0x000000021d3000 0x000000021f6000 0x00000000000000 rw- [heap]
0x007ffd9c547000 0x007ffd9c568000 0x00000000000000 rw- [stack]
0x007ffd9c581000 0x007ffd9c584000 0x00000000000000 r-- [vvar]
0x007ffd9c584000 0x007ffd9c585000 0x00000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x00000000000000 --x [vsyscall]
```

Therefore, we can write arbitrary pointer inside `.fini_array` section to do the ROP.

[EXP](./3x17/exp_3x17.py)

## dubblesort

Solved 2022/08/31

Through some simple reverse engineering, we can find there is an array bounds write when we input the numbers. However, all mitigations are turn on so that we cannot directly write into the return address (no info of the base addresses also unable to cross the stack canary). 

When debugging the program, I found that when we input the name into a name array, there are some preexisting address inside the name array. After crafting the input, we are able to get the leak.   

But still can't cross the wall of canary. So I wen to find the source code of `scanf` function. The following code is copied from https://code.woboq.org/userspace/glibc/stdio-common/vfscanf-internal.c.html

```c
/* other code */
...
        case L_('u'):        /* Unsigned decimal integer.  */
          base = 10;
          goto number;
        case L_('d'):        /* Signed decimal integer.  */
          base = 10;
          flags |= NUMBER_SIGNED;
          goto number;
        case L_('i'):        /* Generic number.  */
          base = 0;
          flags |= NUMBER_SIGNED;
        number:
          c = inchar ();
          if (__glibc_unlikely (c == EOF))
            input_error ();
          /* Check for a sign.  */
          if (c == L_('-') || c == L_('+'))
            {
              char_buffer_add (&charbuf, c);
              if (width > 0)
                --width;
              c = inchar ();
            }

/* other code */
...
```

If we just input `+/-` and nothing else, the `width` will become `0` and will not change the original buffer. So, use this we could bypass the canary. 

**IMPORTANT NOTICE**

The binary works under the environment of `libc-2.23`. So we will have to use `Ubuntu 16.04` to do this (or get the correct version of `ld-2.23.so` and `LD_PRELOAD` the libc). I take reference of God n132's blog to get the correct offset. Deciding to setup multiple docker image for pwn. 

[EXP](./dubblesort/exp_dubblesort.py)

## hacknote

Solved 2022/10/15

Tipically, when seeing the name "note", "message" in the title, then there is a high probability relates to the heap exploitation. So as this challenge.

After reverse the program, it has total 3 functionalities: adding note, delete note, read note. It is obvious that there is a Use After Free (UAF) vulnerbility in the delete note section. 

```c
  if ( notes[v1] )
  {
    free(*((void **)notes[v1] + 1));
    free(notes[v1]);
    puts("Success");
  }
```

Also, the logic of `malloc`ing heap is vulnerable. Here is the data structure for each note:

```c
struct {
    void *func_ptr;
    char *contents;
} note;
```

For eazy to use, the programmer wrap up a puts function and put its pointer into the `func_ptr` part and take the `contents` (which is a ptr) as the only argument. So the exploitation will be easy that first use puts to leak out the libc address and then do arbitrary command execution using `system`. 

[EXP](./hacknote/exp_hacknote.py)

## silver_bullet

Solved 2022/10/15

The vulnerability happend in `power_up` function that when it update the bullet description, is uses the `strcat` function, which will automatically null termitates the string after concatenation. In coincidence, the variable which stores the length lies just after it on the stack. Therefore, we could bypass the length check and perform buffer overflow attacks. 

```c
strncat(dest, s, 48 - *((_DWORD *)dest + 12));
```

[EXP](./silver_bullet/exp_bullet.py)

## applestore

Solved 2022/10/29

To understand this challenge, we should first understand the logic behind it. It is an apple sale store and we could buy iPhone from it. The data structure to store the iPhone is a double linked list. When we add a phone to cart, it links the new phone at the end of the linked list. When we remove a phone from cart, it will unlinkit from the cart, but didn't free the alloced memory (but this is not the vulnerbility)

```c
struct device
{
  char *name;
  int price;
  device *next;
  device *prev;
};
```

Then, the vulnerability on this challenge is quite obvious: in `checkout` function, there is an iPhone8 bonus will be added into the cart if we manage to get total price of 7174. But this iPhone8 is a memory location on the stack, whill allow us to leak the information from it. 

We could use the input to overwrite this stack location and get arbitrary read. However, I can't find a way to exploit it even if I get everything I want (libc, stack, base). I am trying to overwrite the return address but since the code segment in libc is not writable, there will be a segfault caused by the logic in `delete` shown below:

```c
    if ( idx == v3 )
    {
      v4 = next->next;
      prev = next->prev;
      if ( prev )
        prev->next = v4;
      if ( v4 )
        v4->prev = prev;
      printf("Remove %d:%s from your shopping cart.\n", idx, next->name);
      return __readgsdword(0x14u) ^ v7;
    }
```

So here I reference the blog from god `n132`, he uses a technic called `got hijack`. Since the program's `handler` function will read user input each time for choices, we could overwrite the `ebp` to poision the stack frame of the `handler`. When it reads from the user input to the "stack", it actually overwrite it into the got table of `atoi`, which will be then called immediatly. Since we already get everything we need, the exploit will then be easy to implement. 

[EXP](./applestore/exp_applestore.py)

## re-alloc

Solved 2023/6/25

It is a classic menu-driven heap challenge. But this challenge only use realloc to manipulate heap, which will slightly different from normal heap challenges. There are three main functions: `allocate, reallocate, rfree`. `allocate()` will call `realloc(NULL, size)` to malloc new heap region. `reallocate()` will call `realloc(old_ptr, size)` to modify the memory region. `rfree()` will call `realloc(old_ptr, 0)` to free the malloced region and clear out the pointer entry. And in total, we only have 2 pointer entry for heap allocation. 

Since `rfree()` already give us an example that we could use `realloc()` to free a memory region, `reallocate()` also can do it and leave with a dangling pointer for us to use (UAF). What's more, the libc given by the challenge is glibc2.29. After carefully examine the source code, we could have following simplified code:

```c
void *
__libc_realloc (void *oldmem, size_t bytes)
{
  // Code...

  if (bytes == 0 && oldmem != NULL)
  {
    __libc_free (oldmem); return 0;
  }
  if (oldmem == 0)
    return __libc_malloc (bytes);

  // Code...

  newp = _int_realloc (ar_ptr, oldp, oldsize, nb);

  // Some check to newp...

  return newp;
}

void*
_int_realloc(mstate av, mchunkptr oldp, INTERNAL_SIZE_T oldsize,
	     INTERNAL_SIZE_T nb)
{
  // Some check to size, ptr...

  if ((unsigned long) (oldsize) >= (unsigned long) (nb))
    {
      /* already big enough; split below */
      newp = oldp;
      newsize = oldsize;
    }
  else
    {
      /* Try to expand forward into top */
      if (next == av->top &&
          (unsigned long) (newsize = oldsize + nextsize) >=
          (unsigned long) (nb + MINSIZE))
        {
          set_head_size (oldp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
          av->top = chunk_at_offset (oldp, nb);
          set_head (av->top, (newsize - nb) | PREV_INUSE);
          check_inuse_chunk (av, oldp);
          return chunk2mem (oldp);
        }

      /* Try to expand forward into next chunk;  split off remainder below */
      else if (next != av->top &&
               !inuse (next) &&
               (unsigned long) (newsize = oldsize + nextsize) >=
               (unsigned long) (nb))
        {
          newp = oldp;
          unlink_chunk (av, next);
        }

      /* allocate, copy, free */
      else
        {
          newmem = _int_malloc (av, nb - MALLOC_ALIGN_MASK);
          if (newmem == 0)
            return 0; /* propagate failure */

          newp = mem2chunk (newmem);
          newsize = chunksize (newp);

          /*
             Avoid copy if newp is next chunk after oldp.
           */
          if (newp == next)
            {
              newsize += oldsize;
              newp = oldp;
            }
          else
            {
	      memcpy (newmem, chunk2mem (oldp), oldsize - SIZE_SZ);
              _int_free (av, oldp, 1);
              check_inuse_chunk (av, newp);
              return chunk2mem (newp);
            }
        }
    }

    // Some more check try to free old space
}
```

After debugging and source code examination, if we want to realloc a slightly bigger chunk, we will fall into the branch: `Try to expand forward into next chunk;`, which directly modify the heap metadata to extend the chunk. So the attack chain is clear: 

```
alloc -> UAF -> tcache poison -> realloc to leave the poisoned chain in tcache -> arbitrary write to achieve libc base
```

At the end of attacking chain, I choose to overwrite the got table of `atoll(input)` to be the plt of `printf` since it is used in `read_long` to receive user's choice. It directly use user input for its parameters, which easily form a format string attack to leak addresses.   

[EXP](./re-alloc/exp_re-alloc.py)

## tcache_tear

Solved 2023/6/28

The libc version this challenge uses is 2.27, which is very early version of tcache feature. Tcache was introduced into libc from 2.26. It do speed up the allocation process, but it abandoned many necessary security checks for this new feature. This challenge is a good enxample. Early version of tcache struct:

```c
#if USE_TCACHE
 
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
```

We could see that it only contains one pointer to the next, and **NO CHECKS ON DOUBLE FREE**. You can free a chunk arbitrary times and tcache chain will always loop back to itself. This clearly is a tcache poison vulnerability which could easily grant us arbitrary write previliege. 

The next step is to do the exploit. After examination, the got is not writable and no function pointers inside the binary. Which means that we need to find a way to leak out libc first. The `info` function looks suspicious, it just prints out the `Name` that we enter to the program. The purpose of this might be able to leak something out from the `.bss` segment.

After some search on heap exploits, I found that House of spirit could be a way. We could use the `Name` field in the `.bss` segment to make a fake chunk. Arbitrary write from tcache poison can be used to make the follow chunks to bypass the checks. The structure looks like this:

```
prev_size     cur_size
---------------------- name ptr
0             0x501
.bss name fake chunk
...
----------------------
0             0x21
0             0
----------------------
0             0x21
0             0
----------------------
```

With the structure above, we could free the fake chunk in the `.bss` segment and it will be put into the unsorted bin (when size larger than 0x408, it cannot fit into tcache). By the time it was put into the unsorted bin, it will have two pointers (prev, next) points to the main arena, which then leaks the libc address by the `info` function.

With the libc address, we could easily overwrite the function pointers in libc, for example: `__free_hook`. `one_gadget` will help us to do the one shot exploit XD

[EXP](./tcache_tear/exp_tcache_tear.py)

## seethefile

Solved 2023/6/30

The challenge give us arbitrary file read previlege. We can read any files on the machine except the flags. One common trick is to use `/proc/self/maps` to get the memory mapping to leakout addresses. So we could easily get libc address from the file read.

Then we need to consider how to do the exploit. When exiting the program, it let us write our name and close the `fp`. There is an overflow when reading the names, so we could overwrite the file pointer to some fake address and craft exploits. 

```s
.bss:0804B260 ; char name[32]
.bss:0804B260 name            db 20h dup(?)           ; DATA XREF: main+9F↑o
.bss:0804B260                                         ; main+B4↑o
.bss:0804B280                 public fp
.bss:0804B280 ; FILE *fp
.bss:0804B280 fp              dd ?                    ; DATA XREF: openfile+6↑r
.bss:0804B280                                         ; openfile+AD↑w ...
.bss:0804B280 _bss            ends
```

For the `FILE` / `_IO_FILE` struct, we could checkout the [source code](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/libio.h#L241) for further information. More important part is how to achieve the attack. By comparing with the source code of `fclose` and analyzing the decompiled code from `libc.so`, after a bunch of checks on the struct, it will execute `_IO_FINISH (fp);` which will call the function pointer in `vtable`'s `finish` section with the argument `fp` of type `FILE *`. Since we have full control of the fake struct, we could also modify `vtable` pointer to point to anywhere we want. 

Now it's time to discuss how to bypass the checks. By analyzing decompiled code, we could see that it will first compare `fp->flags & 0x2000` with `0`. If it is `0`, then jump to `LABEL_19` and compare `v3 = fp->flags & 0x8000` with `0`. If it isn't `0`, it will call  the function pointer in `LABEL_20`, which is in the `vtable`.

```c
int __cdecl fclose(_BYTE *a1)
{
  // Variables declarations
  _EBX = &tbyte_1B0000;
  if ( a1[70] )
    return fclose_0(a1);
  v2 = *(_DWORD *)a1;
  if ( (*(_DWORD *)a1 & 0x2000) != 0 )
  {
    IO_un_link(a1);
    v2 = *(_DWORD *)a1;
    if ( (BYTE1(*(_DWORD *)a1) & 0x80u) != 0 )
      goto LABEL_11;
  }
  else
  {
    v3 = *(_DWORD *)a1 & 0x8000;
    if ( (v2 & 0x8000) != 0 )
      goto LABEL_19;
  }
  _EDX = *((_DWORD *)a1 + 18);
  v5 = __readgsdword(8u);
  if ( v5 != *(_DWORD *)(_EDX + 8) )
  {
    _ECX = 1;
    v7 = __readgsdword(0xCu) == 0;
    if ( !v7 )
      __asm { lock }
    __asm { cmpxchg [edx], ecx }
    if ( !v7 )
      sub_F1AE0(_EDX);
    _EDX = *((_DWORD *)a1 + 18);
    v2 = *(_DWORD *)a1;
    *(_DWORD *)(_EDX + 8) = v5;
  }
  ++*(_DWORD *)(_EDX + 4);
LABEL_11:
  v3 = v2 & 0x8000;
  if ( (v2 & 0x2000) != 0 )
  {
    v8 = IO_file_close_it_0(a1);
    if ( (*(_DWORD *)a1 & 0x8000) == 0 )
      goto LABEL_13;
    goto LABEL_20;
  }
LABEL_19:
  v8 = v2 << 26 >> 31;
  if ( !v3 )
  {
LABEL_13:
    v9 = (_DWORD *)*((_DWORD *)a1 + 18);
    v7 = v9[1]-- == 1;
    if ( v7 )
    {
      v9[2] = 0;
      if ( __readgsdword(0xCu) )
        __asm { lock }
      v7 = (*v9)-- == 1;
      if ( !v7 )
        sub_F1B10();
    }
  }
LABEL_20:
  (*(void (__stdcall **)(_BYTE *, _DWORD, int, int, int, int, int))(*(_DWORD *)&a1[(char)a1[70] + 148] + 8))(
    a1,
    0,
    v13,
    v14,
    v15,
    v16,
    v17);
  // Other code
}
```

We could craft our fake struct's `flags` field easily bypass the checks, but after successfully called `system`, the argument is `(char *)fp`, which also in the `flags` field. Unfortunately, `/bin` cannot bypass the checks. But what if we leave `flags` as non-null characters and execute the command from behind by using `;` to split commands? Then the final exploit call will be `system("\x??\x??\x??\x??;/bin/ls")`. It can still give use the shell!

[EXP](./seethefile/exp_seethefile.py)

## death_note

Solved 2023/7/7

After checksec, it has RWX segments, which probably will be code injection / shellcoding style challenge. Also, no libc is given, which also means the binary is probably enough for solving the challenge.

> However, I found in my machine, Ubuntu 23.04, not sure if it is the kernel enable some protection for binaries, I cannot get any `RWX` segment except the stack, even I patch it with glibc 2.23. But the searches shows that the shellcoding should be the intended solution (at least heap is `RWX`, not on the stack).

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments
```

After examine the decompiled code, we could see that when inputing the index, it can be negative, which cause arbitrary write pointer overwrite. The next step will be how to write printable ascii shellcode.

```c
idx = read_int();
if ( idx > 10 )
{
  puts("Out of bound !!");
  exit(0);
}
```

I choose to overwrite `GOT` of the `free` function because we can choose what to "free" and it is a free pointer to allow us to enter strings like `/bin/sh`, which will be really helpful. So here is the context when entering shellcode region after we added a note with content `/bin/sh`.

```
─────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x09ce4008  →  "/bin/sh"
$ebx   : 0x0
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffa6493c  →  0x08048878  →  <del_note+81> add esp, 0x10
$ebp   : 0xffa64968  →  0xffa64978  →  0x00000000
$esi   : 0xf7f3a000  →  0x001b1db0
$edi   : 0xf7f3a000  →  0x001b1db0
$eip   : 0x09ce4018  →  0x00005050 ("PP"?)
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
─────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffa6493c│+0x0000: 0x08048878  →  <del_note+81> add esp, 0x10   ← $esp
0xffa64940│+0x0004: 0x09ce4008  →  "/bin/sh"
0xffa64944│+0x0008: 0x00000002
0xffa64948│+0x000c: 0xffa64968  →  0xffa64978  →  0x00000000
0xffa6494c│+0x0010: 0x08048842  →  <del_note+27> mov DWORD PTR [ebp-0xc], eax
0xffa64950│+0x0014: 0x08048be4  →  "Your choice :"
0xffa64954│+0x0018: 0xf7f3a000  →  0x001b1db0
0xffa64958│+0x001c: 0xffa64978  →  0x00000000
```

And luckily, `ebx, ecx, edx` are all `0` when entering the shellcode region. We only need to config `eax` and transfer the pointer to `ebx`. And `push e*x & pop e*x` are valid ascii assembly code after compile! The final point is just to change some instruction to `int 0x80` syscall instruction to allow us to make the call, which is easy after computed the offset from the pointer of `/bin/sh`. 

I reference this [site](https://nets.ec/Ascii_shellcode) and some of my own tests for ascii shellcoding. 

[EXP](./death_note/exp_death_note.py)
