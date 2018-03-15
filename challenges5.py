#
#  Challenges5.py
#


import sys
import secrets

print("Welcome, I am starting on your computation of a ^ b mod m")
a = 2988348162058574136915891421498819466320163312926952423791023078876139
b = 2351399303373464486466122544523690094744975233415544072992656881240319
m = 10 ** 40
print(pow(a, b, m))

print("Now I am starting on the actual challenge. See if we get the same key in both cases.")

p=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
 
g = 2

a = secrets.randbelow(p)
b = secrets.randbelow(p)

ga = pow(g, a, p)
gb = pow(g, b, p)

s1 = pow(ga, b, p)
s2 = pow(gb, a, p)

print("s1 = ", s1 )
print("s2 = ", s2)
