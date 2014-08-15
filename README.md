中文版说明请向下滚动.

Enclib
======

Enclib is an enhanced encryption library wrapper for Python by @exted (http://extedluo.com)

WARNING: The library itself is still under active development. Algorithms may be modified without backwards compatibility support. Please DO NOT use it in production environment until the stable version is released. 

## Features

- Cascaded encryption (CAST5-Blowfish-AES) 
- Built-in key strengthening function which increases the difficult of brute-force attack and rainbow table attack.
- Built-in version identification function

## Requirements

- Python 2.7
- Pycrypto 2.6.1 (https://www.dlitz.net/software/pycrypto/)

## Example

```python
#!/usr/bin/env python

from enclib import *

rawtext="This is the content."
key="password"
enc=Enclibv1()
enctext = enc.encrypt(key, rawtext)
print enctext.encode('hex')
rawtext = enc.decrypt(key, enctext)
print rawtext
```

## Security Audit

You are welcome to audit the scripts and provide feedback on its functions or vulnerability.


Enclib
======

Enclib 是一个增强型 Python 加密库。 
作者: @exted (http://extedluo.com)

警告: 截至当前 Enclib 目前仍处在初步开发阶段。在稳定版本发布之前，该库的算法可能会被更改而不提供向后的兼容支持，所以请暂时不要用在生产环境当中。

## 特色

- 层叠加密算法 (CAST5-Blowfish-AES) 
- 内置密匙增强功能。该功能可以增加暴力破解或者利用彩虹表破解的难度。
- 内置版本核对功能。

## 要求

- Python 2.7
- Pycrypto 2.6.1 (https://www.dlitz.net/software/pycrypto/)

## 例子
```python
#!/usr/bin/env python

from enclib import *

rawtext="This is the content."
key="password"
enc=Enclibv1()
enctext = enc.encrypt(key, rawtext)
print enctext.encode('hex')
rawtext = enc.decrypt(key, enctext)
print rawtext
```

## 安全审核

欢迎任何人审核该库的代码并向我们提供反馈。
