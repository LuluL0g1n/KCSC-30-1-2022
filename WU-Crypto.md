# Warmup
## Đề bài
[warmup.txt](https://github.com/LuluL0g1n/KCSC-30-1-2022/files/7968683/warmup.txt)
## Cách giải
Đề bài cho X với Y, nhìn khá giống bit 1 với 0
```python
a='XYXXYXYYXYXXXXYYXYXYXXYYXYXXXXYYXYYYYXYYXXYYXYXXXYYYXXYXXYYXXYXYXYXYYYYYXYYYXYXYXYXYYYYYXYXYXXYXXXYYXXYYXYYXXXXYXYYXXYXXXYXYYXXYXYXYYYYYXYXYYYYYXYXYYYYYXXYYYYYYXYYYYYXY'
for i in a:
    if i == 'X':
        print('1',end='')
    else:print('0',end='')
```
ta được dãy bit: 101101001011110010101100101111001000010011001011100011011001101010100000100010101010000010101101110011001001111010011011101001101010000010100000101000001100000010000010

Ngược lại, với 'Y' = 1, 'X' = 0, ta được dãy: 010010110100001101010011010000110111101100110100011100100110010101011111011101010101111101010010001100110110000101100100010110010101111101011111010111110011111101111101

Ta đưa lên CyberChef mục Magic
![image](https://user-images.githubusercontent.com/97771705/151759874-ef65d966-6153-4bcf-bf45-14eb564a9596.png)
>Flag:KCSC{4re_u_R3adY___?}

# Advanced Caesar
## Đề bài
```python
import string
import random

table = string.ascii_letters+string.digits+string.punctuation
len_table = len(table)

def encrypt(plaintext,key):
    ciphertext = ""
    for char in plaintext:
        char_index = table.index(char)
        char_index = (char_index+key)%len_table
        ciphertext = ciphertext+table[char_index]
    return ciphertext

key = random.randint(0,15012022)
flag = "KCSC{????????????????????}"
ciphertext = encrypt(flag,key)

f = open("advanced_caesar_output.txt","w")
print(ciphertext,file=f)
```

[advanced_caesar_output.txt](https://github.com/LuluL0g1n/KCSC-30-1-2022/files/7968692/advanced_caesar_output.txt)

## Cách giải
Nhìn tên đề bài là biết phải sử dụng mã Caesar, nhanh chóng đưa lên https://www.dcode.fr/caesar-cipher

![image](https://user-images.githubusercontent.com/97771705/151751276-0c155564-ef45-4080-a69e-3a6c5e9ae9b1.png)

Có vẻ giống KCSC{CaeSaR}.... Nhưng chắc chắn chưa phải flag

"Dễ thế thì đố làm gì"-author challenge từng nói

Đọc lại code, mình phát hiện flag được encrypt theo 
```python
table = string.ascii_letters+string.digits+string.punctuation
```
tức là gồm có cả số, chữ cái viết hoa viết thường và cả các kí tự đặc biệt;điều mà trên dcode không có

Thế thì phải viết 1 code decrypt thôi :),nhưng cần key.

Mình phát hiện key là 15, vì mã hoá kí tự K thành kí tự Z cần key là 15, C thành R cũng như vậy

Code decrypt(chính là code encrypt thôi, nhưng sửa xíu):
```python
import string
import random

table = string.ascii_letters+string.digits+string.punctuation
len_table = len(table)

ciphertext = "ZR7RlRptHpGjEGDJCsjDuj$DJn"
def decrypt(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        char_index = table.index(char)
        char_index = (char_index-key)%len_table
        plaintext = plaintext+table[char_index]
    return plaintext 
print(decrypt(ciphertext,15))
```

>Flag: KCSC{Caesar_pround_of_You}

# RSA baka
## Đề bài
[RSA_baka_output.txt](https://github.com/LuluL0g1n/KCSC-30-1-2022/files/7968776/RSA_baka_output.txt)

```python
from Crypto.Util.number import *

p = getPrime(256)
q = getPrime(256)
N = p*q
e = 65537
#why don't encrypt word by word in rsa ?
def encrypt(m):
    arr = []
    for char in m:
        arr.append(pow(ord(char),e,N))
    return arr

flag = "KCSC{????????????}"
ciphertext = encrypt(flag)
f = open("RSA_baka_output.txt","w")
print(f"N = {N}",file=f)
print(f"e = {e}",file=f)
print(f"ciphertext = {ciphertext}",file=f)
```
## Cách giải
>Hint: why don't encrypt word by word in rsa ?
Mã RSA: plantext ^ e = ciphertext (mod N)

Bài này mã hoá từng kí tự trong flag, và những kí tự(in được) này khi chuyển thành số nguyên sẽ không lớn hơn 128(xem bảng mã ASCII).

Mình biết các bạn đang nghĩ gì :)

Ơ, thế chỉ cần dò xem trong khoảng từ 1 đến 128, số nào thoả mãn công thức RSA là sẽ dò flag à

Đúng là cái đồ BAKA :)))
Code decrypt:
```python
ciphertext = [6490383453148831791818993448967555326156406011524488283342444556015426035759283788898481214198017189839052330624465635904654671502305598200350391968359607, 6114971306814510652226742282811400638090222521432110725688758966397446941318910032628316773459153344590657355652030404276773084433432660472787242141470270, 8255895453382135243139177315155394996634115859947684841234171271344367006987590376749610310728021170713417080083764157154940776479381742677549303790871867, 6114971306814510652226742282811400638090222521432110725688758966397446941318910032628316773459153344590657355652030404276773084433432660472787242141470270, 6602197633859720657587771157089685381603279647463736462392427769595789419221836744809641076890681210330212229469859112392984609921415686976803741623714461, 2413403103993978259606073853249912236932168564522092606962260363965206845206549360121050502230510073122519269723019921011775250713125781096215517552356129, 10234290580931305426193975982170864306373191634019788474520694898790164297975489696680597308948107329978895383237422445498353087690954001043107129284082808, 7336998612016305807202568883328160445095741929564108010434042898356567235223907992499410853800121620237604543518901363400336568026032197145035086846809682, 6114971306814510652226742282811400638090222521432110725688758966397446941318910032628316773459153344590657355652030404276773084433432660472787242141470270, 2958303022499369421389255163855041595852481624503815710227882428094513247057611560837751329875032862142590414989053243468265592040758615651637411711856001, 5249461015250236017494123466707195975796572794929891529363137136092468317942817132027440508125446525676989895818408612885379492127986620311545402652523615, 6935612593707356754842735032374896819175698256183093602527162610981621701714443696456342323885087786931262075663680592876316541546396875142621074111793166, 2935264391388604858377955344531955758810135103530349998914281877849803290322247699515000382817770308687266012722494905696513633203323723939581072734109104, 5526687546529371001521004625585578041770528727075302146086576010123401756163503485005583969602327587176472910127932482214478294301439473348514563396320212, 81688865939358112907090842501804856726826851902318443303326465615374997739879230408855444202559675815925578017785277665573281646246014297396740297259710, 8255895453382135243139177315155394996634115859947684841234171271344367006987590376749610310728021170713417080083764157154940776479381742677549303790871867, 7038198964745707190068002741225996062333697108556030805460748357918047748867654039976030223685622056096737610973997377137045828927594438793109735839403274, 1183511481948457031447390450771565242216568974691535243213295795583400913901864614352243986177208688390850980208658304695828746671850626216638436059635901]
N = 10887224132998565184671212889792167391999693945789218525362414954367270673441409014921387325344338535971177549868678239683398861737372077927406255931268559
e = 65537
for arr in ciphertext:
    for i in range(128):
        if pow(i,e,N)==arr:
            print(chr(i),end='')
```
>Flag: KCSC{D1sCr3te_RSA}

# SQuiz Game
## Đề bài
nc -v 45.77.39.59 3901

# Cách giải
Khi connect vào nc -v 45.77.39.59 3901 , đề bài có dạng

![image](https://user-images.githubusercontent.com/97771705/151755066-aca72cbe-3f5c-4f91-8486-bf9f43942367.png)

Vấn đề tại đây là Quadratic Residue - Thặng dư bậc hai

Các bạn tìm hiểu thêm tại :http://mathscope.org/showthread.php?t=8104

Đề yêu cầu phải qua 100 câu hỏi mới cho flag

Code:
```python
from pwn import *
host="45.77.39.59"
port=3901
r = remote(host,port)
r.recvuntil(b"p = ") #đọc đến "p =  "thì dừng
p=eval(r.recvline().strip().decode())#lấy giá trị của dòng và gán cho p
for i in range(100):
    r.recvuntil(b"a = ")
    a=eval(r.recvuntil(b" ").strip().decode()) #lấy giá trị của dòng đến kí tự " " và gán cho a
    r.recvuntil(b"residual? ")
    a2=pow(a,(p-1)//2,p)
    if a2==1: #Điều kiện cần và đủ để a là thặng dư bậc hai mod p (p nguyên tố lẻ)
        r.sendline(b"YES") #gửi giá trị YES đến server
    else:
        r.sendline(b"NO")
    print(r.recvline())
print(r.recvline())
```

>Flag: KCSC{---L3g3nDrE_sYmB0L---}

# Rand0m
## Đề bài
Requirement: python 3.9
[Rand0m_output.txt](https://github.com/LuluL0g1n/KCSC-30-1-2022/files/7969005/Rand0m_output.txt)
```python
import random
magicNumber = 0x??????
assert magicNumber <= 0xffffff
random.seed(magicNumber)

def xor(a,b):
    return bytes([x^y for x,y in zip(a,b)])'''
'''
flag = b'KCSC{???????????????????????????????????????????}'
key = random.randbytes(len(flag))

cipher = xor(flag,key)
f = open("Rand0m_output.txt","w")
print(cipher,file=f)
```

# China
## Đề bài
[china_output.txt](https://github.com/LuluL0g1n/KCSC-30-1-2022/files/7969010/china_output.txt)
```python
from Crypto.Util.number import *

#Sau cuộc chiến tranh Trung-Nhật (1894-1895) các nước đế quốc gồm : Đức, Anh, Pháp, Nga và Nhật bắt đầu xâu xé chiếc bánh ngọt Trung Quốc

flag_China = b'KCSC{fakeFlagggggggggggggggggggggggggggggggggggggggggggggggggggg}'
flag_China = bytes_to_long(flag_China)
Germany = getPrime(512)
England = getPrime(256)
France = getPrime(128)
Russia = getPrime(96)
Japan = getPrime(64)

f = open("china_output.txt","w")
print(f"Germany = {Germany}",file=f)
print(f"flag_China/Zmod(Germany) = {flag_China%Germany}",file=f)
print(f"England = {England}",file=f)
print(f"flag_China/Zmod(England) = {flag_China%England}",file=f)
print(f"France = {France}",file=f)
print(f"flag_China/Zmod(France) = {flag_China%France}",file=f)
print(f"Russia = {Russia}",file=f)
print(f"flag_China/Zmod(Russia) = {flag_China%Russia}",file=f)
print(f"Japan = {Japan}",file=f)
print(f"flag_China/Zmod(Japan) = {flag_China%Japan}",file=f)
```

# DES Weakness
## Đề bài
```python
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from pwn import xor

IV = os.urandom(8)
FLAG = b'KCSC{????????????????????????????????????????????????????}'

def encrypt(plaintext,key):
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    if (len(plaintext) % 8 != 0):
        plaintext = pad(plaintext,8)
    plaintext = xor(plaintext, IV)
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    ciphertext = xor(ciphertext, IV)
    return ciphertext.hex()

plaintext = b"nhap bat ky".hex()
key = b"8bytekey".hex()

ciphertext = encrypt(plaintext,key)
encrypted_flag = encrypt(FLAG.hex(),key)

print(f"{ciphertext = }")
print(f"{encrypted_flag = }")
```
nc -v 45.77.39.59 3900
