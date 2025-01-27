from des import DesKey
import time

from Ciphers.ProjectBlockCipher import ProjectBlockCipher
from Utilities.CipherUtilities import text_to_binary

start_time = time.time()
for _ in range(0, 1000):
    key0 = DesKey(b"some key")
    t = key0.encrypt(b"any long message")
end_time = time.time()

# محاسبه میانگین زمان برای رمزگذاری
encryption_time_avg = (end_time - start_time) / 10000
print(f"Average encryption time: {encryption_time_avg:.10f} seconds")

start_time = time.time()
x = ProjectBlockCipher()
key = text_to_binary("12345678909876543210")
pt = text_to_binary("ahmadahmadahmadahmad")
for _ in range(0, 1000):
   tt = x.encrypt(pt, key)
end_time = time.time()

encryption_time_avg = (end_time - start_time) / 10000
print(f"Average encryption time: {encryption_time_avg:.10f} seconds")
