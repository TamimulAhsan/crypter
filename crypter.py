import base64
# Atbash cipher encryption
def atbash_cipher_encrypt(txt):
    dictonary = {'A': 'Z', 'B': 'Y', 'C': 'X', 'D': 'W', 'E': 'V',
                 'F': 'U', 'G': 'T', 'H': 'S', 'I': 'R', 'J': 'Q',
                 'K': 'P', 'L': 'O', 'M': 'N', 'N': 'M', 'O': 'L',
                 'P': 'K', 'Q': 'J', 'R': 'I', 'S': 'H', 'T': 'G',
                 'U': 'F', 'V': 'E', 'W': 'D', 'X': 'C', 'Y': 'B',
                 'Z': 'A', ' ': ' ', 'a': 'z', 'b': 'y', 'c': 'x',
                 'd': 'w', 'e': 'v', 'f': 'u', 'g': 't', 'h': 's',
                 'i': 'r', 'j': 'q', 'k': 'p', 'l': 'o', 'm': 'n',
                 'n': 'm', 'o': 'l', 'p': 'k', 'q': 'j', 'r': 'i',
                 's': 'h', 't': 'g', 'u': 'f', 'v': 'e', 'w': 'd',
                 'x': 'c', 'y': 'b', 'z': 'a'
                 }

    splitted_txt = ([*txt])

    for i in splitted_txt:
        if i not in dictonary:
            print(i, end='')

        else:
            print(dictonary[i], end='')

# Atbash cipher decryption
def atbash_cipher_decrypt(cipher_text):
    dictonary = {'A': 'Z', 'B': 'Y', 'C': 'X', 'D': 'W', 'E': 'V',
                 'F': 'U', 'G': 'T', 'H': 'S', 'I': 'R', 'J': 'Q',
                 'K': 'P', 'L': 'O', 'M': 'N', 'N': 'M', 'O': 'L',
                 'P': 'K', 'Q': 'J', 'R': 'I', 'S': 'H', 'T': 'G',
                 'U': 'F', 'V': 'E', 'W': 'D', 'X': 'C', 'Y': 'B',
                 'Z': 'A', ' ': ' ', 'a': 'z', 'b': 'y', 'c': 'x',
                 'd': 'w', 'e': 'v', 'f': 'u', 'g': 't', 'h': 's',
                 'i': 'r', 'j': 'q', 'k': 'p', 'l': 'o', 'm': 'n',
                 'n': 'm', 'o': 'l', 'p': 'k', 'q': 'j', 'r': 'i',
                 's': 'h', 't': 'g', 'u': 'f', 'v': 'e', 'w': 'd',
                 'x': 'c', 'y': 'b', 'z': 'a'
                 }

    splitted_cipher = ([*cipher_text])

    for i in splitted_cipher:
        if i not in dictonary:
            print(i, end='')

        else:
            print(dictonary[i], end='')


# The karaca's encryption Algorithm...
def karacha_encrypt(word):
    dicts = {'a': '0', 'e': '1', 'i': '2', 'o': '3', 'u': '4'}
    final_word = ''
    for i in range(len(word)):
        final_word += word[len(word)-i-1]

    for i in final_word:
        if i in dicts.keys():
            final_word = final_word.replace(i, dicts[i])

    return final_word + 'aca'

#The karacha's decryption algorithm
def karacha_decrypt(word):
    dicts = {'a': '0', 'e': '1', 'i': '2', 'o': '3', 'u': '4'}
    final_word = ''
    for i in range(0, len(word)):
        final_word = final_word + word[len(word)-i-1]
    for i in final_word:
        if i in dicts.keys():
            final_word = final_word.replace(i, dicts[i])
    return final_word + 'aca'

#Cipher encrypt_decrypt
def ceaser_cipher_encrypt(a,b):
    ans = ""

    for i in range(len(a)):
        ch = a[i]
        if ch==" ":
            ans+=" "

        elif (ch.isupper()):
            ans += chr((ord(ch) + b-65) % 26 + 65)

        else:
            ans += chr((ord(ch) + b-97) % 26 + 97)

    return ans

#Ceaser cipher decrypt without shift value
def ceaser_cipher_decrypt_bruteforce(c):
    Letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    for i in range(len(Letters)):
        translated = ""
        for j in c:
            if j in Letters:
                num = Letters.find(j)
                num = num -i

                if num<0:
                    num = num + len(Letters)
                translated = translated + Letters[num]

            else:
                translated = translated + j

        print(f'Shift Value {i}: {translated}')

#Ceaser Cipher decrypt with shift value
def ceaser_cipher_decrypt(d,e):
    Letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    message=""
    for i in d:
        if i in Letters:
            pos = Letters.find(i)
            new_pos = (pos-e) %26
            new_char = Letters[new_pos]
            message+=new_char

        else:
            message+=i

    return message

# Morse code Encoder
def morse_encoder(text):
    char_to_dots = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', ' ': ' ', '0': '-----',
        '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....',
        '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        '&': '.-...', "'": '.----.', '@': '.--.-.', ')': '-.--.-', '(': '-.--.',
        ':': '---...', ',': '--..--', '=': '-...-', '!': '-.-.--', '.': '.-.-.-',
        '-': '-....-', '+': '.-.-.', '"': '.-..-.', '?': '..--..', '/': '-..-.',
    }
    for key in text:
        print(char_to_dots[key.upper()], end=' ')

# Morse code Decoder
def morse_decoder(text):
    char_to_dots = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', ' ': ' ', '0': '-----',
        '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....',
        '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        '&': '.-...', "'": '.----.', '@': '.--.-.', ')': '-.--.-', '(': '-.--.',
        ':': '---...', ',': '--..--', '=': '-...-', '!': '-.-.--', '.': '.-.-.-',
        '-': '-....-', '+': '.-.-.', '"': '.-..-.', '?': '..--..', '/': '-..-.',
    }
    reversed_char_to_dots = {v: k for k, v in char_to_dots.items()}
    splitted_morse = text.split()

    for i in splitted_morse:
        print(reversed_char_to_dots[i], end='')

#Base64 encode
def base64_enc(text):
    text_in_bytes = text.encode("ascii")
    base64_bytes = base64.b64encode(text_in_bytes)
    base64_string = base64_bytes.decode("ascii")

    return base64_string

#Base64 decode
def base64_dec(text):
    b64_in_bytes = text.encode("ascii")
    b64_in_bytes2 = base64.b64decode(b64_in_bytes)
    plain_text = b64_in_bytes2.decode("ascii")

    return plain_text



print('Hi I am Crypter, an expert of cryptography. I will try my best to help you solve your cryptographic Problem. Let us begin.')
enc_or_dec = input('What do you want to do?\n\t1. Encrypt\n\t2. Decrypt\n')

if enc_or_dec == '1':
    enc_type = input('''Please choose your desired encryption type:
    1. Atbash Cipher
    2. Karacha's encryption algorithm
    3. Ceaser Cipher
    4. Morse Code
    5. Base64\n''')

    if enc_type == '1':
        enc_1 = input('\n\tAtbash Cipher\nEnter Text to encrypt: ')
        f'Here is your encrypted text: {atbash_cipher_encrypt(enc_1)}'

    elif enc_type == '2':
        enc_2 = input("\n\tKaracha's Encryption Algorithm\nEnter Plain text: ").lower()
        print(f"Here's your message: {karacha_decrypt(enc_2)}")

    elif enc_type == '3':
        enc_3 = input('\n\tCeaser Cipher\nEnter Text to Encrypt: ')
        enc_shift_value = int(input('Enter shift value: '))
        print(ceaser_cipher_encrypt(enc_3,enc_shift_value))

    elif enc_type == '4':
        enc_4 = input('\n\tMorse Code\nEnter Plain Text: ')
        f'Here is your encoded Morse Code: {morse_encoder(enc_4)}'

    elif enc_type == '5':
        enc_5 = input('\n\tBase64\nEnter Text: ')
        print(f"Here's your base64 encoded text: {base64_enc(enc_5)}")

    else:
        print('Invalid Input')

elif enc_or_dec == '2':

    dec_type = input('''What do you want to decrypt:
    1. Atbash Cipher
    2. Karacha's decryption algorithm
    3. Ceaser Cipher
    4. Morse Code
    5. Base64\n''')

    if dec_type == '1':
        dec_1 = input('\n\tAtbash Cipher\nEnter cipher text: ')
        f"Decrypted Message: {atbash_cipher_decrypt(dec_1)}"

    elif dec_type == '2':
        dec_2 = input("\n\tKaracha's decryption Algorithm\nEnter cipher text: ")
        print(f'Decrypted text: {karacha_decrypt(dec_2)}')

    elif dec_type == '3':

        dec_3 = input('\n\tCeaser Cipher\nEnter text: ').upper()
        aa = input('Do you know shift value? y/n:  ').lower()

        if aa == 'y':
            shift_val = int(input('Enter shift value: '))
            print(f"Here's your decrypted text: {ceaser_cipher_decrypt(dec_3,shift_val)}")

        else:
            ceaser_cipher_decrypt_bruteforce(dec_3)

    elif dec_type == '4':
        dec_4 = input('\n\tMorse Code\nEnter encoded text: ')
        f"Decoded text: {morse_decoder(dec_4)}"

    elif dec_type == '5':
        dec_5 = input('\n\tBase64\nEnter encoded text: ')
        print(f"Here's your message{base64_dec(dec_5)}")

    else:
        print('Invalid Input.')
        
else:
    print('Invalid Input')
