from Crypto.Cipher import AES
from ctr import aes_ctr
from secrets import token_bytes, randbits
import hashlib


class SuperSafeServer:
    def __init__(self):
        self._key = token_bytes(AES.key_size[2])
        self._nonce = randbits(64)
        # Creamos una propiedad que se denomina hash y es privada, ahí se almacenará el hash.
        self._hash = ''

    def create_cookie(self, user_data):
        if ';' in user_data or '=' in user_data:
            raise Exception("Caracteres ilegales en user data")
        cookie_string = "cookieversion=2.0;userdata=" + user_data + ";safety=veryhigh"

        # Hasheamos la cookie y la almacenamos.
        self._hash = hashlib.sha256(aes_ctr(cookie_string.encode(), self._key, self._nonce)).hexdigest()

        return aes_ctr(cookie_string.encode(), self._key, self._nonce)

    def check_admin(self, cookie):
        # Validación adicional
        if hashlib.sha256(cookie).hexdigest() != self._hash:
            return False

        cookie_string = aes_ctr(cookie, self._key, self._nonce).decode()

        print(cookie_string)

        return ';admin=true;' in cookie_string


def forge_cookie():
    server = SuperSafeServer()

    user_data = "retoAesCtr?admin-true"  # TODO: Modificar user_data inicial
    cookie = server.create_cookie(user_data)


    # TODO: Modificar la cookie

    # Primero se analiza la longitud de la cookie. Sabemos que AES genera bloques de 16 bytes (128 bits).

    cipher_blocks = [(lambda c: list(c[blk - 16:blk]))(cookie) for blk in range(16, len(cookie) + 16, 16)]

    # cookieversion=2. | 0;userdata=retoA | esCtr?admin-true | ;safety=veryhigh
    # Sabemos que donde tenemos que modificar es en el bloque 3.


    cipher_blocks[2][5] = cipher_blocks[2][5] ^ ord('?') ^ ord(';')
    cipher_blocks[2][11] = cipher_blocks[2][11] ^ ord('-') ^ ord('=')

    cipher_block_joined = [(lambda c: bytes(c))(blk) for blk in cipher_blocks]
    cipher_blocks = b''.join(cipher_block_joined)

    if server.check_admin(cipher_blocks):
        print("Acceso Admin!")
    else:
        print("Acceso no Admin o denegado")


if __name__ == '__main__':
    forge_cookie()
