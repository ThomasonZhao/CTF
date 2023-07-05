# UIUCTF 2023

## Fast Calculator

The code logic is simple. The program is a staticly linked calculator support floating point calculation. It will behave normally until you calcuate the "secret result." Then it will try to do calculation and decode the flag for you based on the result of calculation. Unfortunately, the flag is a fake flag, so there must be something wrong with the decode process. 

After examine the code, we can find that it will test the result of calculation based on the result of the function below. But the function `isNotNumber()` and `isInfinity()` will always return false. I originally thought it is legit operations, but after our teammates solve the challenge, I finally found the key point is here lol.

```c
_BOOL8 __fastcall gauntlet(double a1)
{
  return (unsigned __int8)isNegative(a1) || (unsigned __int8)isNotNumber(a1) || (unsigned __int8)isInfinity(a1);
}
```

So the solve logic is straightforward now: grab flag data, grab operations that it made, calculate, fix the `gauntlet` logic, flag got. 

Base on the stack frame given by ida, We can easily dump out the source flag data

```
gef➤  x/50b $rbp - 0x70
0x7fffffffdb40: 0x4b    0xc3    0xe1    0x01    0x00    0xb9    0xee    0x10
0x7fffffffdb48: 0xee    0x4b    0xf0    0xa4    0x78    0x21    0x38    0xcb
0x7fffffffdb50: 0xea    0x2a    0x21    0x6b    0xce    0x83    0x46    0xe8
0x7fffffffdb58: 0x41    0xa7    0x8c    0x2c    0x09    0xcf    0xf5    0xa0
0x7fffffffdb60: 0xa1    0x72    0x27    0x08    0x60    0x28    0xa9    0x20
0x7fffffffdb68: 0x66    0xb3    0xab    0x35    0xa4    0xe9    0x00    0x00
0x7fffffffdb70: 0xb8    0xdb
```

We also need the call logic of function `calculate` to get the operations. After debugging, we can find that the operands are on the stack, like shown below. We can easily write a [python helper script](./Fast_Calculator/gdbhelper.py) (or normal gdb script if you want) to dump out the operations.

```
gef➤  x/3gx $rsp
0x7fffffffac50: 0x0000000000000025      0x4073a3c584d895d0
0x7fffffffac60: 0xc0757ccd8b26163a
```

Put everything into python, done! Another alternative could be patching the elf to make it work as intended.

[SOLVER](./Fast_Calculator/solver_calc.py)

## Vimjail 1.5

This challenge restrict user into a vim's insert mode (but cannot insert anything). We need to get out of jail and readout the flag. After looking really carefully into the vim documentation, I founnd that `CTRL-R =` can have some special operations. It may allow us to enter the [expression](https://vimdoc.sourceforge.net/htmldoc/eval.html). 

We can easily get the content of the flag by using `readfile()` built-in function provided by this feature. However, the expression is evaluated by the `CTRL-R =` will be input directly into the file (which we cannot access). We need a way to output the flag. But variables can only be defined in normal mode or command-line mode, the expression can only evaluate the variables. Accidentally when I test on my local vim, I found that in the expression mode, I can still use `CTRL-R` to output contents from the registers (`{0-9a-z"%#*+:.-=}`). If we could store stuff in register, we could output it on the screen. Luckily, we have built-in function `setreg()`. 

- Press `CTRL-R`
- Press `=`
- Type `setreg('0', readfile("/flag.txt"))`
- Press `Enter`
- Press `CTRL-R`
- Press `=`
- Press `CTRL-R`
- Press `0`
- Flag show on the screen

## Vimjail 2.5

More restrictive vimjail, this time it banned all lower case letters and some characters. But this time our target is to "quit" the vim.

> I double quote "quit" here means we don't actually need to. 

In order to execute multi argument function, like `setreg()`, we need to type `,`. But it is in the ban list. The key point here is to use the viminfo given by the challenge. After we do `CTRL-R =`, we could again press `CTRL-R` then press `up-arrow` to access the history shown in the viminfo. This will allow us have the **important** `,` character and then we can map it to some other registers. With `tolower()` function, we can almost fully bypass the ban list. 

> Are you asking how to type `setreg()` to map `,`? You can use `Tab` to auto complete any function after you do `CTRL-R =`!