from ntru import NTRU

# ----------------------  PARAMETROS ----------------------------------------------
# Importancia de la elección de p y q en la generación de las llaves
#
# En el esquema NTRU, la llave privada f debe ser invertible en los anillos 
# R_p = Z_p[x] / (x^N - 1) y R_q = Z_q[x] / (x^N - 1). Sin embargo, la existencia 
# de estos inversos no está garantizada para cualquier polinomio f generado al azar.
#
# La dificultad para encontrar un f invertible depende de la elección de p y q:
# - Si p y q son primos pequeños, la probabilidad de que un f aleatorio sea 
#   invertible en ambos anillos es menor, lo que puede requerir varias iteraciones 
#   para encontrar un candidato adecuado.
# - Si p y q son primos más grandes o están bien elegidos, es más probable que 
#   f tenga inverso en ambos anillos en menos intentos.
#
# Como consecuencia, bajo ciertas elecciones de parametros, puede ser necesario
# multiples ejecuciones del progama para encontrar un f que cumpla con las
# condiciones necesarias para la construccion de las llaves del esquema 
# --------------------------------------------------------------------------------
N = 7
p = 3
q = 41
d = 2

ntru = NTRU(N, p, q, d)

# Generar llaves
h, f, g, f_p = ntru.gen_keys()

# Mensaje aleatorio
m = ntru.gen_ternary_polynomial(N, d, d)
print("Mensaje original:", m)

# Encriptar mensaje
ciphertext = ntru.encrypt(m, h)
print("Texto cifrado:", ciphertext)

# Desencriptar mensaje
plaintext = ntru.decrypt(ciphertext, f, f_p)
print("Texto descifrado:", plaintext)

