
## 🍁Expanding the Capabilities of YARA Rules

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
        [![LinkedIn](https://img.shields.io/badge/LinkedIn-Profile-blue)](https://www.linkedin.com/in/nikhil--chaudhari/)
        [![Medium](https://img.shields.io/badge/Medium-Writeups-black)](https://medium.com/@nikhil-c)


- When crafting YARA rules, incorporating wildcards and jumps can significantly expand the rule’s detection capabilities, making it more flexible and versatile. These powerful features allow you to create rules that match a broader range of patterns, thus enhancing your threat hunting and malware detection capabilities.

## WILD-CARDS :
In YARA, wild cards allow you to specify flexible matching patterns for bytes or nibbles in a hexadecimal string. We can use the question mark (?) as a wild card, and the tilde (~) as the not operator.

**Example 1:**
```
$hex_string1 = { F4 23 ~00 62 B4 }
        $hex_string2 = { F4 23 ~?0 62 B4 }
```
**explaination :** In the example above, in $hex_string1 we have a byte prefixed with a tilde (~), which is the not operator. This defines that the byte in that location can take any value except the value specified. In this case the first string will only match if the byte is not 00. The not operator can also be used with nibble-wise wild-cards, so the second string $hex_string2 will only match if the second nibble is not zero.  
**Example 2:**
```
$hex_string3 = { F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }
```

**Explaination :** YARA rule employs wild cards for flexible matching. It matches files if the string contains the specified fixed bytes F4 23 at the beginning, followed by either 62 B4 or 56 or any two nibbles between 45 and 67, and finally, ends with 45. Any other combination of bytes at these positions will not result in a match.

**JUMP :**

Jumps, represented by [min-max], enable matching variable-length sequences between defined patterns. For example:
```
$hex_string = { F4 23 [4-6] 62 B4 }
```
**Explaination :** This rule will match if any sequence of 4 to 6 bytes occurs between F423 and 62B4. Jumps offer flexibility, allowing different patterns within the specified range. Any of the following strings will match the pattern:
```
F4 23 01 02 03 04 62 B4
F4 23 00 00 00 00 00 62 B4
F4 23 15 82 A3 04 45 22 62 B4
```