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

## Silver Bullet

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