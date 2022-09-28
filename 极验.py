import uuid
import random
import requests
import time
import re
import json
from my_cryptio import Rsa, Cbc
from urllib.request import urlretrieve
from gap import get_distance
from trajectory import get_slide_track


class JiYan:
    def __init__(self):
        self.uid = uuid.uuid1().__str__()
        headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343.42'
        }
        self.session = requests.session()
        self.session.headers = headers
        self.captchaId = ''
        self.gt = ''

    def timeC(self):
        t = int(time.time() * 1000)
        return str(t)

    def get_demo(self):
        url = 'https://www.geetest.com/adaptive-captcha-demo'
        resp = self.session.get(url)
        demo_js = re.findall('href="(/_next/static.*?adaptive-captcha-demo\\.js)"', resp.text)[0]
        return 'https://www.geetest.com' + demo_js

    def get_captchaId(self, demo_url):
        resp = self.session.get(demo_url)
        self.captchaId = re.findall('captchaId:"(.*?)"', resp.text)[0]

    def get_load(self):
        url = 'https://gcaptcha4.geetest.com/load'
        params = {
            'captcha_id': self.captchaId,
            'challenge': self.uid,
            'client_type': 'web',
            'risk_type': 'slide',
            'lang': 'zh',
            'callback': 'geetest_' + self.timeC()
        }
        resp = self.session.get(url, params=params)
        load_info = resp.text.replace(f'{params["callback"]}(', '')[:-1]
        return json.loads(load_info)

    def info_analysis(self, load_info):
        url = 'https://static.geetest.com/'
        bg_url = url + load_info['data']['bg']
        slice_url = url + load_info['data']['slice']
        x = self.get_x(bg_url, slice_url)
        slide_track = get_slide_track(x)
        lot_number = load_info['data']['lot_number']
        payload = load_info['data']['payload']
        process_token = load_info['data']['process_token']
        return {
            'x': x,
            'lot_number': lot_number,
            'payload': payload,
            'process_token': process_token,
            'track': slide_track
        }

    def get_x(self, bg_url, slice_url):
        urlretrieve(bg_url, './bg.png')
        urlretrieve(slice_url, './slice.png')
        x = get_distance('./bg.png', './slice.png')
        return x

    def get_setLeft(self, track):
        setLeft = 0
        for i in track:
            setLeft += i[0]
        return setLeft

    def get_passtime(self, track):
        passtime = 0
        for i in track:
            passtime += i[2]
        return passtime

    def get_userresponse(self, setLeft):
        e = 340
        i = .8876 * e / 300
        return setLeft / i

    def structure(self, info):
        track = info['track']
        setLeft = self.get_setLeft(track)
        userresponse = self.get_userresponse(setLeft)
        e = {
            "setLeft": setLeft,
            "track": track,
            "passtime": self.get_passtime(track),
            "userresponse": userresponse,
            'pow_sign': info['process_token'],
            "device_id": "A59C",
            "lot_number": info['lot_number'],
            "geetest": "captcha",
            "lang": "zh",
            "ep": "123",
            "nz8c": "255401529",
            "em": {
                "ph": 0,
                "cp": 0,
                "ek": "11",
                "wd": 1,
                "nt": 0,
                "si": 0,
                "sc": 0
            }
        }
        return e

    def genKey(self):
        t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        n = ''
        for i in range(16):
            n += random.choice(t)
        return n

    def encry(self, e, key):
        cbc = Cbc(key, '0000000000000000')
        _1 = cbc.encrypt(json.dumps(e))
        rsa = Rsa()
        _2 = rsa.Rencrypt(key)
        return str(_1) + str(_2)

    def verify(self, w, info):
        url = 'http://gcaptcha4.geetest.com/verify'
        params = {
            'captcha_id': self.captchaId,
            'client_type': 'web',
            'lot_number': info['lot_number'],
            'risk_type': 'slide',
            'payload': info['payload'],
            'process_token': info['process_token'],
            'payload_protocol': 1,
            'pt': 1,
            'callback': 'geetest_' + self.timeC(),
            'w': w
        }
        resp = self.session.get(url, params=params)
        print(resp.text)

    def run(self):
        demo_js = self.get_demo()
        self.get_captchaId(demo_js)
        load_info = self.get_load()
        info = self.info_analysis(load_info)
        e = self.structure(info)
        key = self.genKey()
        w = self.encry(e, key)
        self.verify(w, info)
        # print(a)


if __name__ == '__main__':
    j = JiYan()
    j.run()
