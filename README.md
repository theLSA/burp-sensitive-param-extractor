# burp-sensive-param-extractor

## 概述

检测并提取请求参数中的敏感参数名，如userid，username，方便测试越权漏洞，并形成敏感参数字典。

## 快速开始

param-regular.cfg：参数正则配置文件，id表示请求参数中包含id的参数，如userid，idcard等。

sensitive-params.txt：参数字典文件。

支持4种参数检测

self.requestParamDict['urlParams'] = []

self.requestParamDict['BodyParams'] = []

self.requestParamDict['cookieParams'] = []

self.requestParamDict['jsonParams'] = []

界面右侧的列表即参数正则，可实时增删，删除只需单击列表元素再点击删除按钮即可。

![](https://github.com/theLSA/burp-sensitive-param-extractor/raw/master/demo/bspe00.jpg)

## 反馈

[issues](https://github.com/theLSA/burp-sensitive-param-extractor/issues)

