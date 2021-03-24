#!/usr/bin/python3

import hashlib, sys

salt=""
password=""

if len(sys.argv)==2:
	password = sys.argv[1]
	salt = ""
elif len(sys.argv)==3:
	password = sys.argv[1]
	salt = sys.argv[2]
else:
	print('masher v1.0 - trustwave spiderlabs')
	print('[!] No input specified. Please use the format: masher.py <password> <salt>')
	print('[-] The salt is optional')
	sys.exit()

print('masher v1.0 - trustwave spiderlabs')
print('[-] using password: '+password)
print('[-] using salt: '+salt)

m = hashlib.md5()
m.update(password.encode('UTF-8'))
print('MD5:       '+ m.hexdigest())

m = hashlib.sha1()
m.update(password.encode('UTF-8'))
print('SHA-1:     '+ m.hexdigest())

m = hashlib.sha224()
m.update(password.encode('UTF-8'))
print('SHA-224:   '+ m.hexdigest())

m = hashlib.sha256()
m.update(password.encode('UTF-8'))
print('SHA-256:   '+ m.hexdigest())

m = hashlib.sha384()
m.update(password.encode('UTF-8'))
print('SHA-384:   '+ m.hexdigest())

m = hashlib.sha512()
m.update(password.encode('UTF-8'))
print('SHA-512:   '+ m.hexdigest())

m = hashlib.sha3_224()
m.update(password.encode('UTF-8'))
print('SHA3-224:  '+ m.hexdigest())

m = hashlib.sha3_256()
m.update(password.encode('UTF-8'))
print('SHA3-256:  '+ m.hexdigest())

m = hashlib.sha3_384()
m.update(password.encode('UTF-8'))
print('SHA3-384:  '+ m.hexdigest())

m = hashlib.sha3_512()
m.update(password.encode('UTF-8'))
print('SHA3-512:  '+ m.hexdigest())

print('*MIX AND MATCH*')
m = hashlib.md5()
m.update((password+salt).encode('UTF-8'))
print('MD5(PASSSALT):                  '+m.hexdigest())

m = hashlib.md5()
m.update((salt+password).encode('UTF-8'))
print('MD5(SALTPASS):                  '+m.hexdigest())

m = hashlib.md5()
m.update((salt+password+salt).encode('UTF-8'))
print('MD5(SALTPASSSALT):              '+m.hexdigest())

m = hashlib.md5()
m2 = hashlib.md5()
m.update((salt+password).encode('UTF-8'))
m2.update(m.digest())
print('MD5(MD5(SALTPASS)):             '+m2.hexdigest())

m = hashlib.md5()
m2 = hashlib.md5()
m.update(password.encode('UTF-8'))
m2.update(m.digest())
print('MD5(MD5(PASS):                  '+m2.hexdigest())

m = hashlib.md5()
m2 = hashlib.md5()
m3 = hashlib.md5()
m.update(salt.encode('UTF-8'))
m2.update(password.encode('UTF-8'))
m3.update(m.digest()+m2.digest())
print('MD5((MD5SALT)(MD5PASS)):        '+m3.hexdigest())

m = hashlib.sha1()
m.update((password+salt).encode('UTF-8'))
print('SHA1(PASSSALT):                 '+m.hexdigest())

m = hashlib.sha1()
m.update((salt+password).encode('UTF-8'))
print('SHA1(SALTPASS):                 '+m.hexdigest())

m = hashlib.sha1()
m.update((salt+password+salt).encode('UTF-8'))
print('SHA1(SALTPASSSALT):             '+m.hexdigest())

m = hashlib.sha1()
m2 = hashlib.sha1()
m.update((salt+password).encode('UTF-8'))
m2.update(m.digest())
print('SHA1(SHA1(SALTPASS)):           '+m2.hexdigest())

m = hashlib.sha1()
m2 = hashlib.sha1()
m.update(password.encode('UTF-8'))
m2.update(m.digest())
print('SHA1(SHA1(PASS):                '+m2.hexdigest())

m = hashlib.sha1()
m2 = hashlib.sha1()
m3 = hashlib.sha1()
m.update(password.encode('UTF-8'))
m2.update(m.digest())
m3.update(m2.digest())
print('SHA1(SHA1(SHA1(PASS):           '+m3.hexdigest())

m = hashlib.sha1()
m2 = hashlib.sha1()
m3 = hashlib.sha1()
m.update((salt+password).encode('UTF-8'))
m2.update(m.digest())
m3.update(m2.digest())
print('SHA1(SHA1(SHA1(SALTPASS)):      '+m3.hexdigest())

m = hashlib.sha1()
m2 = hashlib.sha1()
m3 = hashlib.sha1()
m.update(salt.encode('UTF-8'))
m2.update(password.encode('UTF-8'))
m3.update(m.digest()+m2.digest())
print('SHA1((SHA1 SALT)(SHA1 PASS)):   '+m3.hexdigest())