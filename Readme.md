
# YARA Lab-Setup 

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
        [![LinkedIn](https://img.shields.io/badge/LinkedIn-Profile-blue)](https://www.linkedin.com/in/nikhil--chaudhari/)
        [![Medium](https://img.shields.io/badge/Medium-Writeups-black)](https://medium.com/@nikhil-c)

## 🍁Introduction
This lab is design to  installation and configuration of YARA in linux machine. also we will see how we can create rules for malware or threat detection with realworld examples.

## 🔗Prerequisites
- Basic understanding of Command-line.
- Malware basics.

## 📝Requirements:
- Vmware
- Ubuntu 22.04 installed on Virtual machine.

## 👩🏻‍🔬🧪Lab set-up
## ⚙️ YARA installation
1. Clone the YARA repository from virustotal github page.
```
Git clone https://github.com/VirusTotal/yara.git

```
Latest releases of Yara can be found at : https://github.com/virustotal/yara/releases.

2. Now Install the Dependencies using below command.
```
sudo apt-get install automake libtool make gcc pkg-config flex bison
```
3. Run below commands to setup Yara.

```
wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.tar.gz
tar -zxf v4.3.2.tar.gz
cd yara-4.3.2
./bootstrap.sh
./configure --with-crypto --enable-profiling --enable-macho --enable-dex --enable-cuckoo --enable-magic --enable-dotnet
make
sudo make install
sudo apt-get remove -y libyara9 python3-yara #Removes any existing installation from distro repos
```
4. Verify YARA installation : After installation, you can verify that YARA is working correctly by running below command.
```
yara --version

```
## Yara Syntax
YARA rules are written in files with the .yar extension. Each YARA rule is composed of several sections, enabling a structured and organized approach to defining detection patterns.

### Import Module :
To enhance the functionality of YARA rules, you can import other external YARA modules. These modules provide additional features and capabilities for your rules. For example, importing the “pe” module allows you to analyze Windows PE files more effectively:
```
import pe
```

### Rule name :
A YARA rule must have a user-defined name that helps organize the rules within a ruleset. Giving meaningful names to rules is essential for easy identification and management. For instance:
```
rule my_first_rule
```

### Meta Data :
Adding meta data to your YARA rule can be incredibly valuable, especially when sharing your rules with the community or your colleagues. Meta data provides additional information about the rule’s purpose, author, and description. It aids in better understanding the rule’s intent and usage. Here’s how you can include meta data in your rule:
```
meta:
  author = "Nikhil"
  description = "My First yara rule"
  date = "2024-11-07"
```

### Strings :
Strings are the heart of a YARA rule and define the patterns you want to search for in a file. YARA supports various types of strings, including plain text strings, hexadecimal strings, and regular expressions.

**Plain Text Strings** : These strings are enclosed in double quotes and can be used to search for specific text patterns in files:
**Hexadecimal Strings** : Hex strings allow you to search for binary patterns in files. You can use wildcards (represented by “?”) to match variable bytes.
**Regaular expression** : YARA supports regular expressions to create more flexible and complex pattern-matching rules. . For instance, you can use a regular expression to search for MD5 hashes.
```
strings:
  $text_string = "text here"
  $hex_string = { E2 34 ?? C8 A? FB }   
  $re1 = /md5: [0-9a-fA-F]{32}/
```

### Condition :
The condition part of a YARA rule is crucial, as it determines when the rule will be triggered based on the presence or absence of specific strings or characteristics in the target file. Understanding various ways to craft conditions enhances your ability to create effective and precise YARA rules. Below are the some of the ways the conditions can be written.

1. **Boolean Logic** : Boolean logic allows you to combine multiple conditions using operators like AND (and), OR (or), and NOT (not). For example:
```
condition: 
  $hex_string and $text_string
```
“The rule will match if both the $hex_string and $text_string are found in the file.”  

2. **Using Quantifiers** : Quantifiers enable you to specify how many times a string or condition should be repeated in the file. YARA supports quantifiers like at least, at most, and any of them. For example:
```
condition: 
  $string1 at least 2 and $string2 at most 4
```
3. **File size Condition** : YARA allows you to incorporate file attributes into conditions. You can use the special attribute $filesize to create conditions based on the size of the file. For example:
```
condition: 
  $filesize < 5MB
```

### Combining Multiple Conditions: 
 Leveraging the power of boolean logic, quantifiers, and file attributes, you can create comprehensive conditions tailored to your specific use case. For example:
 ```
 condition: 
    $filesize < 2MB and ($string1 or $string2) and not $string3
```
“This rule will match if the file size is less than 2 MB , either string1 or string2 is found, but string3 is not found in the file.”

## YARA Scanning
To execute YARA rules and perform scanning, you can use the yara command-line tool. The basic command syntax is as follows:
```
yara [options] <rule_file> <target>
```
#### Example YARA rule
Rule to Detect Common Windows File Paths.
```
// Rule to detect common Windows file paths
import "pe"

rule detect_common_windows_file_paths {
    meta:
        author = "Karan"
        last_updated = "2023-07-27"
        confidence = "medium"
        description = "Detects common Windows file paths in PE files"

    strings:
        $windows_paths = /C:\\(Windows|Program Files|System32|Users\\Public)\\/i

    condition:
        pe.number_of_sections >= 2 and any of them
}
```
“In this YARA rule, we use the pe module to analyze Portable Executable (PE) files and detect common Windows file paths. The rule looks for strings that match typical Windows file paths, such as C:\Windows, C:\Program Files, C:\System32, and C:\Users\Public, regardless of the case. If any of these paths are found within the PE file, the rule will trigger. The condition also ensures that the PE file has at least two sections to increase the accuracy of the detection.”

## 🚩Conclusion
In this project lab we try to clear how to install and configure yara in linux machine. also we try to clear how it works and how we can use it in thread hunting.

