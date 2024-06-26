# zer0ptsCTF 2023

Official repo: https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master

## wise

To be honest, it is a really tough challenge for me. It took around two days for me to finish (with some help from the official wp).

The challenge looks simple, a program written in [crystal programming language](https://crystal-lang.org/reference/1.9/). It is a high level language similar to `python`. By examine the source code, we could easily find something suspicious.

```crystal
  when 4
    print "ID of suspect: "
    STDOUT.flush
    index = id_list.index gets.not_nil!.chomp.to_u64
    if index.nil?
      puts "[-] Invalid ID"
    else
      puts "[+] Marked '#{name_list[index]}' as possible spy"
      suspect = id_list.to_unsafe + index
    end
```

After looking up basic grammar and documentation of crystal, `to_unsafe` is a method for array objects. It will return a pointer to the array. The [document](https://crystal-lang.org/api/1.9.0/Array.html#to_unsafe:Pointer(T)-instance-method) also warned us:

> This method is **unsafe** because it returns a pointer, and the pointed might eventually not be that of self if the array grows and its internal buffer is reallocated.

So the vulnerability here is obvious, there will be a pointer to allow us to control after our array have been realocated. More specifically UAF (Use After Free), but in a high level language. With this, we could easily get the libc address by calculating the offsets. 

> Wait, are you asking how can I know where the program / allocator put our data? We can set the ID for spy! (I think that's the only reason why it provides this function. The author can definitly torture player to search the random IDs themselves XD). So in my solution, I setup the ID to something that will never happened normally in the program: `0x6666666666666666`. I call it ["anchor in the memory."](https://thomasonzhao.cn/2022/04/17/Win10-UWP-Calculator/#Anchor-in-the-memory) By searching this special hex ID, we can easily find when the arrary reallocated, where they move, etc. 

So locking down the data location is easy, but what about exploitation? I found that after the array is relocated, that chunk of memory will be "freed" and will be used by other data. The dangling UAF pointer is used for the free list. Can we do something similar to tcache poison? The answer is "YES"!

To avoid other programming language related data mess up our free chunk, we should make our chunk big enough. The relocation bump is $(2 * (Sn - 1) + 1)$: 4, 7, 13, ... After some tests, I just choose the bump at 25. 

So the process is similar to the tcache poison, after reach the bump of 25 elements, the array will be relocated, old memory chunk is free, we can change spy ID to modify the pointer to do arbitrary write (the size must match the free space of the old array size). 

But, arbitrary write isn't enough for the exploit, we need some address leak. Since we already have write previlege, we can manipulate the array pointer point back to itself. Then by marking spy using the "ID" (pointer of the array), we can have arbitrary read using option 3.

Now all the primitives satisfied, do an exploit will be easy. 

> There are some wired stuff happend when crafting the exploits and overwriting arrary pointer back to itself. I all commented in the exp script, enjoy.

[EXP](./wise/exp_wise.py)