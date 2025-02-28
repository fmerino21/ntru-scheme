import sympy as sp
from sympy.abc import x
from random import shuffle


class NTRU:

    def __init__(self, N, p, q, d):
        self.N = N
        self.p = p
        self.q = q
        self.d = d
        self.mod_poly = sp.Poly(x**N - 1, x) 

        if q <= (6*d + 1)*p:
            raise ValueError("q debe ser mayor que (6d + 1)p para garantizar la correctitud en la desencripción")
    

    def gen_ternary_polynomial(self, N, d1, d2):
        """
        Genera un polinomio ternario con coeficientes en {-1, 0, 1}
        El polinomio generado tiene d1 coeficientes 1 y d2 coeficientes -1
        """
        v = [1]*d1 + [-1]*d2 + [0]*(N-d1-d2)
        shuffle(v)
        return sp.Poly(v, x)


    def poly_mod(self, f, q):
        """ 
        Reduce un polinomio módulo mod_poly en Z_q[x] 
        """
        mod_poly = self.mod_poly
        mod_poly = sp.Poly(mod_poly, x, domain=sp.GF(q))
        prod = f % mod_poly
        return sp.Poly([coef % q for coef in prod.all_coeffs()], x)


    def invert_poly_mod_p(self, f, p):
        """ 
        Intenta encontrar la inversa de f en Z_p[x] / (x^N - 1) 
        """
        N = self.N
        try:
            return sp.invert(f, x**N - 1, domain=sp.GF(p))
        except:
            raise ValueError(f"f no es invertible en Z_{p}[x]")


    def gen_keys(self):
        """
        Algoritmo de generacion de llaves
        Llave publica: h = p * f_q * g
        Llave privada: f, g, f_p
        """
        
        N = self.N
        d = self.d
        p = self.p
        q = self.q
        mod_poly = self.mod_poly

        f = self.gen_ternary_polynomial(N, d+1, d)
        g = self.gen_ternary_polynomial(N, d, d)

        print("---------- Generacion de llaves ---------\n")

        print("f :", f)
        print("g :", g)      

        print("\n---------- Inverso de f en Z_p[x] -------\n")

        f_p = self.invert_poly_mod_p(f, p)            
        f = sp.Poly(f.as_expr(), x, modulus=p)  # Mover los coeficientes de f de Z a Z_p

        print("f   :", f)
        print("f_p :", f_p)

        print("f_p * f :", self.poly_mod(f * f_p, p))


        print("\n---------- Inverso de f en Z_q[x] -------\n")

        f_q = self.invert_poly_mod_p(f, q)   
        f = sp.Poly(f.as_expr(), x, modulus=q)  # Mover los coeficientes de f de Z a Z_q

        print("f   :", f)
        print("f_q :", f_q)

        print("f_q * f :", self.poly_mod(f * f_q, q))


        g = sp.Poly(g.as_expr(), x, modulus=q) # Mover los coeficientes de g de Z a Z_q

        h = self.poly_mod(p * f_q * g, q) 
        h = sp.Poly(h.as_expr(), x, modulus=q)  

        print("\n---------- Llaves -------\n")

        print("Llave publica: ")
        print("h :", h)

        return h, f, g, f_p

    def encrypt(self, m, h):
        """
        Algoritmo para encriptar un mensaje m
        """

        N = self.N
        d = self.d
        q = self.q
    
        r = self.gen_ternary_polynomial(N, d, d)

        # Mover los coeficientes de Z a Z_q   
        r = sp.Poly(r.as_expr(), x, modulus=q)  
        m = sp.Poly(m.as_expr(), x, modulus=q) 

        e = self.poly_mod((h * r) + m, q)
        e = sp.Poly(e.as_expr(), x, modulus=q) # Mover los coeficientes de e de Z a Z_q

        print("\n ------------ Encripcion ------------------\n")
        print("Polinomio aleatorio r: ", r)

        return e

    def decrypt(self, e, f, f_p_inv):
        """
        Algoritmo para desencriptar un texto cifrado
        """
        N = self.N
        q = self.q
        p = self.p

        a = self.poly_mod(f * e, q)
        
        print("\n ------------ Desencripcion ------------------\n")

        print("Polinomio a: ", a)

        # Centro y aplico modulo q
        center_lift = lambda c, q: (c % q - q) if (c % q > q // 2) else c % q
        a_coeffs = [center_lift(c, q) for c in a.all_coeffs()]

        lifted_a = sp.Poly(a_coeffs, x) 
        lifted_a  = sp.Poly(lifted_a.as_expr(), x, modulus=p) # Mover los coeficientes de Z a Z_p       
        
        # Centro y aplico modulo p
        b = self.poly_mod(f_p_inv * lifted_a, p)
        b_coeffs = [center_lift(c, p) for c in b.all_coeffs()]
        lifted_b = sp.Poly(b_coeffs, x)

        return lifted_b
    