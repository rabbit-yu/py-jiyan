import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii


class Rsa:
    def __init__(self):
        e = '010001'
        e = int(e, 16)
        n = '00C1E3934D1614465B33053E7F48EE4EC87B14B95EF88947713D25EECBFF7E74C7977D02DC1D9451F79DD5D1C10C29ACB6A9B4D6FB7D0A0279B6719E1772565F09AF627715919221AEF91899CAE08C0D686D748B20A3603BE2318CA6BC2B59706592A9219D0BF05C9F65023A21D2330807252AE0066D59CEEFA5F2748EA80BAB81'
        n = int(n, 16)
        self.pub_key = rsa.PublicKey(e=e, n=n)

    def Rencrypt(self, pwd):
        text = rsa.encrypt(pwd.encode(), self.pub_key)
        return text.hex()


class Cbc:
    def __init__(self, key, iv):
        # 初始化密钥
        self.key = key
        # 初始化数据块大小
        self.length = AES.block_size
        # 初始化AES,ECB模式的实例
        self.aes = AES.new(self.key.encode("utf-8"), AES.MODE_CBC, iv=iv.encode("utf-8"))
        # 截断函数，去除填充的字符
        self.unpad = lambda date: date[0:-ord(date[-1])]

    def fill_method(self, aes_str):
        '''pkcs7补全'''
        pad_pkcs7 = pad(aes_str.encode('utf-8'), AES.block_size, style='pkcs7')

        return pad_pkcs7

    def encrypt(self, encrData):
        # 加密函数,使用pkcs7补全
        res = self.aes.encrypt(self.fill_method(encrData))
        # 转换为base64
        # msg = str(base64.b64encode(res), encoding="utf-8")
        msg = binascii.b2a_hex(res).decode()

        return msg


if __name__ == '__main__':
    c = Cbc('2510213da5389ac9', '0000000000000000')
    print(c.encrypt('2510213da5389ac9'))

