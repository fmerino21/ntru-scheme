from ntru import NTRU

# Parametros
N = 7
p = 3
q = 41
d = 2

ntru = NTRU(N, p, q, d)

# Generar claves
h, f, g, f_p = ntru.gen_keys()

# Mensaje aleatorio
m = ntru.gen_ternary_polynomial(N, d, d)
print("Mensaje original:", m)

ciphertext = ntru.encrypt(m, h)
print("Texto cifrado:", ciphertext)

plaintext = ntru.decrypt(ciphertext, f, f_p)
print("Texto descifrado:", plaintext)

