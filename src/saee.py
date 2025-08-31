from scapy.all import *
import string
import random
import subprocess
from datetime import datetime
import hashlib
from binascii import unhexlify
import time
import random
import logging
from collections import namedtuple


Point = namedtuple("Point", "x y")
O = 'Origin'

def lsb(x):
    binary = bin(x).lstrip('0b')
    return binary[0]

def legendre(a, p):
    return pow(a, (p - 1) // 2, p)

def tonelli_shanks(n, p):
  
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r
    
    
class Curve():
   

    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def curve_equation(self, x):
       
        return (pow(x, 3) + (self.a * x) + self.b) % self.p

    def is_quadratic_residue(self, x):
   
        return pow(x, (self.p-1) // 2, self.p) == 1

    def valid(self, P):
      
        if P == O:
            return True
        else:
            return (
                (P.y**2 - (P.x**3 + self.a*P.x + self.b)) % self.p == 0 and
                0 <= P.x < self.p and 0 <= P.y < self.p)

    def inv_mod_p(self, x):
       
        if x % self.p == 0:
            raise ZeroDivisionError("Impossible inverse")
        return pow(x, self.p-2, self.p)

    def ec_inv(self, P):
      
        if P == O:
            return P
        return Point(P.x, (-P.y) % self.p)

    def ec_add(self, P, Q):
     
        if not (self.valid(P) and self.valid(Q)):
            raise ValueError("Invalid inputs")

        if P == O:
            result = Q
        elif Q == O:
            result = P
        elif Q == self.ec_inv(P):
            result = O
        else:

            if P == Q:
                dydx = (3 * P.x**2 + self.a) * self.inv_mod_p(2 * P.y)
            else:
                dydx = (Q.y - P.y) * self.inv_mod_p(Q.x - P.x)
            x = (dydx**2 - P.x - Q.x) % self.p
            y = (dydx * (P.x - x) - P.y) % self.p
            result = Point(x, y)

        assert self.valid(result)
        return result

    def double_add_algorithm(self, scalar, P):
       
        assert self.valid(P)

        b = bin(scalar).lstrip('0b')
        T = P
        for i in b[1:]:
            T = self.ec_add(T, T)
            if i == '1':
                T = self.ec_add(T, P)

        assert self.valid(T)
        return T

class Peer:
   
  
   

    def __init__(self, password, mac_address, name):
        self.name = name
        self.password = password
        self.mac_address = mac_address

        
        
        self.p = int('A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377', 16)
        self.a = int('7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9', 16) 
        self.b = int('26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6', 16)
        self.q = int('A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7', 16)
        
        self.curve = Curve(self.a, self.b, self.p)

    def initiate(self, other_mac, k=40):
        
        self.other_mac = other_mac
        found = 0
        num_valid_points = 0
        counter = 1
        n = self.p.bit_length() + 64

        while counter <= k:
            base = self.compute_hashed_password(counter)
            temp = self.key_derivation_function(n, base, 'Dragonfly Hunting And Pecking')
            seed = (temp % (self.p - 1)) + 1
            val = self.curve.curve_equation(seed)
            if self.curve.is_quadratic_residue(val):
                if num_valid_points < 5:
                    x = seed
                    save = base
                    found = 1
                    num_valid_points += 1


            counter = counter + 1

        if found == 0:
            print('No valid point found after  iterations : ' + str(k))
            self.initiate(self.other_mac, k = 40)
        elif found == 1:
        
            y = tonelli_shanks(self.curve.curve_equation(x), self.p)

            PE = Point(x, y)


            assert self.curve.curve_equation(x) == pow(y, 2, self.p)


            self.PE = PE
            assert self.curve.valid(self.PE)

    def commit_exchange(self):
        
   
        random.seed()


        self.private = random.randrange(1, self.p)
        self.mask = random.randrange(1, self.p)

    

       

        self.scalar = (self.private + self.mask) % self.q

      
        if self.scalar < 2:
            raise ValueError('Scalar is {}, regenerating...'.format(self.scalar))

        P = self.curve.double_add_algorithm(self.mask, self.PE)

        self.element = self.curve.ec_inv(P)

        assert self.curve.valid(self.element)




        return self.scalar, self.element

   

    def key_derivation_function(self, n, base, seed):

        combined_seed = '{}{}'.format(base, seed.encode())
        

        random.seed(combined_seed)

   

        randbits = random.getrandbits(n)
        binary_repr = format(randbits, '0{}b'.format(n))

        assert len(binary_repr) == n




        C = 0
        for i in range(n):
            if int(binary_repr[i]) == 1:
                C += pow(2, n-i)





        k = C



        return k

    def compute_hashed_password(self, counter):
        maxm = max(self.mac_address, self.other_mac)
        minm = min(self.mac_address, self.other_mac)
        message = '{}{}{}{}'.format(maxm, minm, self.password, counter).encode()

        H = hashlib.sha256()
        H.update(message)
        digest = H.digest()
        return digest


def handshake(password,mac_STA,mac_AP):
    mac1, mac2 = mac_STA, mac_AP
    sta = Peer(password, mac1, 'STA')
  



    sta.initiate(mac2)
    scalar_sta, element_sta = sta.commit_exchange()


    
    return scalar_sta, element_sta
  

  
  
def generate_Scalar_Finite(password,mac_STA,mac_AP):

	scalar_sta, element_sta = handshake(password,mac_STA,mac_AP)
	

	while len(hex(element_sta[0])) != 67 or len(hex(element_sta[1])) != 67 or len(hex(scalar_sta)) !=67 :
		
		scalar_sta, element_sta = handshake(password,mac_STA,mac_AP)
		
		
		
	scalar = hex(scalar_sta)
	scalar = scalar[2:]
	scalar = scalar[:-1]
	scalar = unhexlify(scalar)
		
	x1=hex(element_sta[0])
	y1 =hex(element_sta[1])
		
	x1 = x1[2:]
	x1 = x1[:-1]
		
	y1 = y1[2:]
	y1 = y1[:-1]
		
	x1 = unhexlify(x1)		
	y1 = unhexlify(y1)
		
	finite = x1 + y1
	
	return scalar, finite
		
	
		


	

	
	
	



  	


