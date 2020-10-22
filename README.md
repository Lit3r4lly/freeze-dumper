# freeze-dumper

freeze-dumper is made for CS:GO cheats development, and contains offsets and netvars dumper that can make your cheats work dynamically.

## Remarks

- Recommended - build for x64 (debug or release mode)
- Run only when CS:GO is running
- Header file will be created in the same folder as the program is running in
- For now, this program is mainly used for CS:GO cheats, but you can also try to customize your own config file for whatever game / process you would like to scan
- Config file should be .txt file and follow the [instructions below](#config-format)

## Features

- [x] offsets dumper
- [ ] netvars dumper

## How does offsets dumping work?

In CS:GO a process memory contains some real-time information about the game, for example: health pointer that points to an area in the module memory which holds the player's health.  
These pointers are called offsets - offsets point to the locations where the desired information is stored at (like the health pointer example).  
  
**So... how can we get these offsets?**  
Offsets are usually represented as hex number (when looking at r/m64 instructions and so on).  
For example -  `mov rax, [module_name.dll + <offset>]`.  
So, what we would like to do is to take the `<offset>` part from the hex characters sequence by using a technique called 'Pattern Scanning'.

**What is Pattern Scanning?**  
First of all, as you know (or not), Valve is changing its offsets every single update,because of that we would like to automate the task of extracting those offsets using "Pattern Scanning".  
Pattern Scanning is a technique which is made for extracting offsets from modules contents and more specifically from the r/m64 instructions as we mentioned above.  
We are implementing this technique by looking for the surrounding instructions code and then extracting the offset from this bytes sequecne.  

**For pattern scanning we need two main elements:**  
`Pattern` - a pattern is a number of instructions that are represented by a byte sequence and includes a specific r/m64 instruction that contains the offset as mentioned above.  
`Mask` -  a mask defines which bytes of your pattern are wildcards and which are not, by using the characters '?' and 'x'.  
The character 'x' means 'byte must match with the one from the module content' and  the character '?' means 'the index of where we can find the offset in the module content respectively with the pattern'  

**For example:**  
Pattern - `\xA1\x00\x00\x00\x00\x33\xD2\x6A\x00\x6A\x00\x33\xC9\x89\xB0`  
Mask -  `x????xxxxxxxxxx`  

To sum it up, we want to make our technique useable, by comparing each byte in the module content with the bytes in the pattern, and if we will end up in the same iteration with a wild card, we will skip this iteration cause we want to be sure that the whole pattern match this part in the module content.  

Fully implementation of the tecnique can be found in the 'Pattern Scanning.c' file.

TADA! we get the offset :)  

## Usage

```
[$] Usage:  
        freeze-dumper.exe <config_path>
[*] Examples:  
        freeze-dumper.exe "config.h"
```

## Config-format

For your convenience, I made a config file (config.txt) which contains the most important signatures, but if you still want to make your own config file, it should be .txt file and follow this format (!):  
```
<process_name>  
<signature_name1> : <module_name1> : <pattern1> : <mask1> : <offset1> : <extra1> :  
<signature_name2> : <module_name2> : <pattern2> : <mask2> : <offset2> : <extra2> :  
<signature_name3> : <module_name3> : <pattern3> : <mask3> : <offset3> : <extra3> :
...
...
<signature_name20> : <module_name20> : <pattern20> : <mask20> : <offset20> : <extra20> :
```

## Build

freeze-dumper can be built with Visual Studio 2019, by opening the .sin file and build the project (Ctrl+Shift+B) in a Release Mode or a Debug Mode, whatever you want to (x64)

## Issues

If you have any issues with this tool, you can ping me on Discord: Lit3r4lly#8336  
If you have some critical bug, open an PR/Issue ticket