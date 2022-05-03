# StrTwins

[![strTwinsCI](https://github.com/AandersonL/strTwins/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/AandersonL/strTwins/actions/workflows/go.yml)

StrTwins is a binary analysis tool, powered by radare, that is capable to find shared code string references between executables and output in JSON, YAML and Yara. 

## How this works

Code string references refer to direct access in the binary code to the string address itself, that's is great filter to detect which visibile strings are actually used inside the software.

So, in other words it means that `strTwins` will look *only* strings that are actually used by the software itself, compute every ocurrencies in all files and output only `shared` string between them.

# Installing

The current version were just tested only on Linux and macOS, but it's possible to compile from source to another system. 

*In order to use strTwins, you will need to have [radare2](https://github.com/radareorg/radare2) installed in your machine.*

### From release
You can just go the [Releases](https://github.com/AandersonL/strTwins/releases) page and grab the binary for your system!

### Compiling from source

As it's written in golang, it's very simple to compile with just:

`go get github.com/AandersonL/strTwins`

And if your `PATH` variable points to your `$GOPATH/bin` directory, you can start use by calling

`$ strTwins -h`


## How this works in practice 

Consider this simple two programs:

```c
// Prog 1
const char* url  = "https://google.com";
const char* url2 = "https://reddit.com";

some_random_function(url, url2);
...

// Prog 2
const char* url  = "https://google.com";
const char* url2 = "https://youtube.com";
some_random_function(url, url2);
```

Running:

> strTwins prog1 prog2 

```
https://google.com:
  widestring: false
  instructions:
  - filename: prog1
    contextdisasm: lea rax, str.https:__google.com
    disasm: lea rax, [rip + 0x2f]
    offset: 4294983530
    funcoffset: 4294983504
  - filename: prog2
    contextdisasm: lea rax, str.https:__google.com
    disasm: lea rax, [rip + 0x10]
    offset: 4294983551
    funcoffset: 4294983536
```

The default output is `YAML`, so here you can see that `https://google.com` is a shared string reference between `prog1` and `prog2` and also you can see what instruction refer to the string address in two formats, a `context assembly` which will replace the string location with a string symbol, `str.https:__google.com`, and a `disasm` that will display the raw asm code in the reference address.

If the reference happens inside a function, it will display the function address in the `funcoffset` key. 

The output is not limited only to YAML, you can easily choose between `json` and `Yara`!

## Usage

You can easily see the use by passing `-h` in the command line:

```
$ ./strTwins -h
Discover shared string references between binaries and output in a variety formats!

Usage:
  strTwins file1, file2... [flags]

Flags:
  -f, --format string     Format to output, available are: json, yaml and Yara! (default "yaml")
  -h, --help              help for strTwins
  -n, --rulename string   Yara rule name, if was choosen as format output!
```


## Example: Emotet malware

Let's use `strTwins` between 2 emotet samples and output in json and Yara:


### JSON output

`$ strTwins tests/emotet/* -f json`

```json
{
 "GradientFill": {
  "WideString": false,
  "Instructions": [
   {
    "Filename": "tests/emotet/87ea8dd7b7e6805738bc4f31778cc37932f4da9615d215b855bde087eb02b547",
    "ContextDisasm": "push str.GradientFill",
    "Disasm": "push 0x40502c",
    "Offset": 4198430,
    "FuncOffset": 4198400
   },
   {
    "Filename": "tests/emotet/000b0cf537e46c5a93de8ec4672450772d247ea5417692a35ef314679f1d4f4d",
    "ContextDisasm": "push str.GradientFill",
    "Disasm": "push 0x40502c",
    "Offset": 4198430,
    "FuncOffset": 4198400
   }
  ]
 },
 "bMgBo2S1*Ki}V~5n28Si#20f~}M4KZ?dy%@nCMnTQJLc*E4bJ|$A8DSZne4pTXEJ%@PfX3mKBgvXa": {
  "WideString": false,
  "Instructions": [
   {
    "Filename": "tests/emotet/87ea8dd7b7e6805738bc4f31778cc37932f4da9615d215b855bde087eb02b547",
    "ContextDisasm": "mov esi, str.bMgBo2S1KiV5n28Si20fM4KZ_dy__nCMnTQJLcE4bJ_A8DSZne4pTXEJ__PfX3mKBgvXa",
    "Disasm": "mov esi, 0x4058c8",
    "Offset": 4205772,
    "FuncOffset": 0
   },
   {
    "Filename": "tests/emotet/000b0cf537e46c5a93de8ec4672450772d247ea5417692a35ef314679f1d4f4d",
    "ContextDisasm": "mov esi, str.bMgBo2S1KiV5n28Si20fM4KZ_dy__nCMnTQJLcE4bJ_A8DSZne4pTXEJ__PfX3mKBgvXa",
    "Disasm": "mov esi, 0x4058c8",
    "Offset": 4205772,
    "FuncOffset": 0
   }
  ]
 },
 "msimg32.dll": {
  "WideString": false,
  "Instructions": [
   {
    "Filename": "tests/emotet/87ea8dd7b7e6805738bc4f31778cc37932f4da9615d215b855bde087eb02b547",
    "ContextDisasm": "push str.msimg32.dll",
    "Disasm": "push 0x405020",
    "Offset": 4198414,
    "FuncOffset": 4198400
   },
   {
    "Filename": "tests/emotet/000b0cf537e46c5a93de8ec4672450772d247ea5417692a35ef314679f1d4f4d",
    "ContextDisasm": "push str.msimg32.dll",
    "Disasm": "push 0x405020",
    "Offset": 4198414,
    "FuncOffset": 4198400
   }
  ]
 }
}
```

### Yara output

`$ strTwins tests/emotet/* -f yara -n emotet_dummy_rule`

```yara
rule emotet_dummy_rule {
	meta:
		description = "Generated rule by strTwins tool"
	strings:
		$0 = "msimg32.dll"
		$1 = "GradientFill"
		$2 = "bMgBo2S1*Ki}V~5n28Si#20f~}M4KZ?dy%@nCMnTQJLc*E4bJ|$A8DSZne4pTXEJ%@PfX3mKBgvXa"
	condition:
		all of them
}
```

*DISCLAIMER: The `yara` format option is a naive output, don't trust your rules to only this attributes, consider strTwins a helper tool to work with a large dataset of malware.* 




# Conclusion

This is a experimental tool, if you find any errors and have ideas for code improvements/new features, feel free to open a PR! 

Thanks.



