# ConfuserEx

[![Build status][img_build]][build]
[![Test status][img_test]][test]
[![CodeFactor][img_codefactor]][codefactor]
[![Gitter Chat][img_gitter]][gitter]
[![MIT License][img_license]][license]

ConfuserEx is a open-source protector for .NET applications.
It is the successor of [Confuser][confuser] project.

ConfuserEx��һ��.NETӦ�ó���Ŀ�Դ�������ܳ���
����[Confuser][confuser]��Ŀ�ļ̳��ߡ�

## Features

* Supports .NET Framework 2.0/3.0/3.5/4.0/4.5/4.6/4.7/4.8
* Symbol renaming (Support WPF/BAML)
* Protection against debuggers/profilers
* Protection against memory dumping
* Protection against tampering (method encryption)
* Control flow obfuscation
* Constant/resources encryption
* Reference hiding proxies
* Disable decompilers
* Embedding dependency
* Compressing output
* Extensible plugin API
* Many more are coming!

# ����֧��.NET Framework 2.0/3.0/3.5/4.0/4.5/4.6/4.7/4.8
������������֧��WPF/BAML��
��Ե�����/̽�����ı���
��ֹ�ڴ�ת��
���۸ı������������ܣ�
����������
����/��Դ����
�������ش���
���÷�������
Ƕ��������
ѹ�����
����չ���API
���๦�ܵ�����
# Usage
# Improved Features ��ԭ��Ľ�����
english | ����
:------------ | :-------------
Automatically load existing plug-ins from the plug-in directory | �Ӳ��Ŀ¼���Զ����ش��ڵĲ��
Add Chinese language resources | �������������Դ

# Custom Plugins �Զ�����ģ���嵥
protection | english | ����
:------------ | :------------ | :-------------
AntiDe4dot | Prevents usage of De4Dot. | ��ֹʹ��De4Dot������
AntiWatermark | Removes the ProtectedBy watermark to prevent Protector detection. | ɾ��ˮӡ���Է�ֹ����⵽������
AntiDump | Prevents the assembly from being dumped from memory. | ��ֹ���ڴ�ת������
Constant | This protection encodes and compresses constants in the code. | �Դ����еĳ������б����ѹ��
EreaseHeader | Overwrites the whole PE Header. | �������PE��ͷ
OpCodeProt | Protects OpCodes such as Ldlfd. | ���������룬����Ldlfd
FakeObfuscator | Confuses obfuscators like de4dot by adding types typical to other obfuscators. | �����ͻ�����������ӵ�ģ���У����ڷ�ֹ����������⡣���� de4dot��
LocaltoField | This protection marks the module with a attribute that discourage ILDasm from disassembling it. | �����������ģ�飬��ֹILDasm��������
Anti DnSpy | Prevents assembly execution if dnspy is detected on disk | ��ֹʹ��DnSpy���Գ���
Anti Virtual Machine | Prevents the assembly from running on a virtual machine. | ��ֹ����������������С�
Mutate Constants | Mutate Contants with sizeofs. | 
New Control Flow | modified version of IntControlFlow from GabTeix. | �µ����̻���ģ��
Reduce Metadata Optimization | Reduces the size of assembly by removing unnecessary metadata such as parameter names, duplicate literal strings, etc. | ͨ��ɾ������Ҫ��Ԫ���ݣ�����������ظ����ı��ַ����ȣ�����С���򼯵Ĵ�С��

# Usage �÷�
```Batchfile
Confuser.CLI.exe <path to project file>
```

The project file is a ConfuserEx Project (`*.crproj`).
The format of project file can be found in [docs\ProjectFormat.md][project_format]

# Advanced function configuration �߼���������
#### �����������ԣ�����ˮӡ��
```C#
[assembly: Obfuscation(Exclude = False, Feature = "-watermark")]
```
#### ����������ԣ�ĳ���������������
```C#
[Obfuscation(Exclude=false, Feature="-rename")]
```

## ���������Ĺ����԰������ų���Ҫ����������Ҫ�������Ĺ���

#### �����ض���[�����ռ�]�ų�[������]��
```XML
<rule pattern="true">
  <protection id="rename" />
</rule>
<rule pattern="namespace('Your.Namespace.Here') and is-type('enum')">
  <protection id="rename" action="remove" />
</rule>
```

#### �����ض���[�����ռ�]�ų��Թ������͵�[������]��
```XML
<rule pattern="inherits('System.Web.UI.Page')" preset="none">
    <protection id="rename">
      <argument name="renPublic" value="false" />
    </protection>
</rule>
```
#### �����ض���[����]�ų�[������]��
```XML
<rule pattern="match-type-name('DataObject')" inherit="false">
    <protection id="rename" action="remove" />
</rule>
```
#### ���[�ǹ���]�ģ���������[�����л�]���Ե������ǿ����������
```XML
<rule pattern="not is-public() and is-type('serializable')">
  <protection id="rename">
    <argument name="forceRen" value="true" />
  </protection>
</rule>
```
#### ������м̳�[ö������]�ģ�������[����]�����ͣ���Ҫ��������
```XML
<rule pattern="inherits('System.Enum') and is-public()" inherit="false">
    <protection id="rename" action="remove" />
</rule>
```

#### ������ý���ģʽ�б�
```XML
or
and
not
module           �ж�ģ������
namespace        �ж������ռ���ȫƥ�䣬֧��һ��������֧������
member-type      �жϳ�Ա���ͣ�֧��һ�����������ò���Ϊtype��method��propertym getter��propertym setter��eventm add��eventm remove��eventm fire��other��field��property��event��module
name             ��ȫƥ������(Name)����֧������
match            ƥ��ȫ����(FullName)��֧�����򣬷���ȫƥ��
match-name       ƥ������(Name)��֧�����򣬷���ȫƥ��
match-type-name  ƥ���������ƣ�֧�����򣬷���ȫƥ��

is-type    �ж��Ƿ�ָ�����ͣ�֧��һ�����������ò���Ϊenum��interface��valuetype��delegate��abstract��nested��serializable
is-public  ָʾ��Ա�ɼ���
inherits   ָʾ�����Ƿ��ָ�����ͼ̳�
has-attr   �Ƚ��Ƿ����ָ�����ԣ�attribute��
full-name  �Ƚ϶���ȫ����definition��
decl-type  �Ƚ���������ȫ����declaring type��
```

```XML
    <protection id="rename">
      <argument name="renameArgs" value="true" />
      <argument name="renPublic" value="true" />
      <argument name="mode" value="decodable" />
      <argument name="password" value="This password is secret" />
    </protection>
    
    ��������ز����б�
    renameArgs   �Ƿ�����������
    forceRen     �Ƿ�ǿ��������
    renPublic    �Ƿ���������������
    renEnum      �Ƿ�������ö��
    password     ������ʱ���������Ƶ�����
```

# Bug Report BUG����

See the [Issues Report][issues] section of website.

# License

Licensed under the MIT license. See [LICENSE.md][license] for details.

# Credits

**[0xd4d]** for his awesome work and extensive knowledge!

[0xd4d]: https://github.com/0xd4d
[build]: https://ci.appveyor.com/project/mkaring/confuserex/branch/master
[codefactor]: https://www.codefactor.io/repository/github/mkaring/confuserex/overview/master
[confuser]: http://confuser.codeplex.com
[issues]: https://github.com/mkaring/ConfuserEx/issues
[gitter]: https://gitter.im/ConfuserEx/community
[license]: LICENSE.md
[project_format]: docs/ProjectFormat.md
[test]: https://ci.appveyor.com/project/mkaring/confuserex/branch/master/tests

[img_build]: https://img.shields.io/appveyor/ci/mkaring/ConfuserEx/master.svg?style=flat
[img_codefactor]: https://www.codefactor.io/repository/github/mkaring/confuserex/badge/master
[img_gitter]: https://img.shields.io/gitter/room/mkaring/ConfuserEx.svg?style=flat
[img_license]: https://img.shields.io/github/license/mkaring/ConfuserEx.svg?style=flat
[img_test]: https://img.shields.io/appveyor/tests/mkaring/ConfuserEx/master.svg?style=flat&compact_message
