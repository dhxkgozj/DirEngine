import re


def Ascii_valid(byte_array):
    text = ""
    next_bit = False
    for i in byte_array:
        if (ord(i)>0x20) and (ord(i)<0x7f):
            next_bit = False
            text += chr(ord(i))
        elif ord(i) == 0x0:
            if(next_bit == True):
                break
            next_bit = True
            continue
        else:
            break
    if(len(text) < 3):
        return False
    return re.sub(r'[^\x20-\x7F]',' ', text)



def Unicode_valid(string):
    try:
        return string.decode('utf-8')
        
    except UnicodeError:
        return False


