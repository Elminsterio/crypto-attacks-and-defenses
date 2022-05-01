from statistics import mean
import base64
import re

english_frequency = {
    b'a': 0.08167,
    b'b': 0.01492,
    b'c': 0.02782,
    b'd': 0.04253,
    b'e': 0.12702,
    b'f': 0.02228,
    b'g': 0.02015,
    b'h': 0.06094,
    b'i': 0.06966,
    b'j': 0.00153,
    b'k': 0.00772,
    b'l': 0.04025,
    b'm': 0.02406,
    b'n': 0.06749,
    b'o': 0.07507,
    b'p': 0.01929,
    b'q': 0.00095,
    b'r': 0.05987,
    b's': 0.06327,
    b't': 0.09056,
    b'u': 0.02758,
    b'v': 0.00978,
    b'w': 0.02360,
    b'x': 0.00150,
    b'y': 0.01974,
    b'z': 0.00074,
}


def otp(data, key):
    out = [(lambda a, b: a ^ b)(*l) for l in zip(data, key)]
    return bytes(out)


def repeatingxor(b, key):
    k = (key * len(b))[0:len(b)]
    return otp(b, k)


def frequency_analysis(text):

    regex = re.compile(b'[^a-zA-Z]')
    alpha = regex.sub(b'', text).decode().lower()

    observed_frequency = {i: 0 for i in list(english_frequency.keys())}
    for char in alpha:
        observed_frequency[char.encode('ascii')] += 1

    observed_list = list(observed_frequency.values())
    expected_list = list(english_frequency.values())

    meanSqErr = mean([(lambda f1, f2: (f1-f2)**(2.0))(*l) for l in zip(expected_list, observed_list)])
    spaces = text.count(b' ')
    symbolFreq = 1.0 - (float(len(alpha) + spaces) / float(len(text)))
    if symbolFreq > 0.7:
        return 1000
    penalizer = 1.0 + (symbolFreq*7)
    return meanSqErr * penalizer


def transpose(m):
    return [bytes([m[j][i] for j in range(len(m))]) for i in range(len(m[0]))]


# group: bytes
def brute_force(group):
    DEBUG = True
    best_k = 0
    best_score = -1
    if (DEBUG):
        print("----------------------------------------------------")
    for i in range(0, 128):
        k = bytes([i])
        plain = repeatingxor(group, k)
        f_score = frequency_analysis(plain)
        if (f_score < 100 and DEBUG):
            print("[" + str(f_score) + "] (" + str(k) + ") " + str(plain))
        if best_score < 0 or f_score < best_score:
            best_k = k
            best_score = f_score
    return best_k


def get_key_many_time_pad(enc_messages):
    groups = transpose(enc_messages)
    key = []
    for g in groups:
        k = brute_force(g)
        key.append(k)
    return b''.join(key)


def decrypted_mssg(k, blocks_mssg):

    message = b''

    for block in blocks_mssg:
        message += otp(block, k)

    return message


ciph_b64 = open("ej1.txt", "r").read()
ciph_b64_decoded = base64.b64decode(ciph_b64)
cipher_on_blocks = [(lambda segment: segment[n-10:n])(ciph_b64_decoded) for n in range(10, len(ciph_b64_decoded), 10)]

print(cipher_on_blocks)

key = get_key_many_time_pad(cipher_on_blocks)

print("key found!")
print(key)
print()
print('Message decrypted:')
print(decrypted_mssg(key, cipher_on_blocks))