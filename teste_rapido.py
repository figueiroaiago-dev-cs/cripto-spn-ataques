import os, random, time
import cipher as C

# 1) ida e volta
for kb in C.KEY_SIZES:
    p = C.cifrar_mensagem("Olá, Renatta! Mensagem de teste do Projeto 1.", "senhaForte#2026", kb)
    assert C.decifrar_mensagem(p, "senhaForte#2026", kb).startswith("Olá")
print("Ida e volta OK (32/64/128 bits)")

# 2) mesma mensagem, mesma senha -> pacotes diferentes (chave dinâmica)
a = C.cifrar_mensagem("oi", "x"); b = C.cifrar_mensagem("oi", "x")
print("Pacotes diferentes p/ mesma msg+senha:", a != b)

# 3) avalanche (1 bit do texto claro) x rodadas, num bloco
rng = random.Random(1)
def hd(x, y): return bin(x ^ y).count("1")
print("\nRodadas | avalanche texto | avalanche chave")
for R in range(1, 11):
    tot_p = tot_k = 0; N = 2000
    for _ in range(N):
        k = os.urandom(16); ks = C.subchaves(k, R)
        x = rng.getrandbits(64); bit = 1 << rng.randrange(64)
        tot_p += hd(C.cifrar_bloco(x, ks, R), C.cifrar_bloco(x ^ bit, ks, R))
        k2 = bytearray(k); k2[rng.randrange(16)] ^= 1 << rng.randrange(8)
        tot_k += hd(C.cifrar_bloco(x, ks, R), C.cifrar_bloco(x, C.subchaves(bytes(k2), R), R))
    print(f"{R:7d} | {100*tot_p/N/64:13.1f}% | {100*tot_k/N/64:13.1f}%")

# 4) velocidade (base p/ força bruta)
ks = C.subchaves(os.urandom(16)); t = time.perf_counter(); n = 50_000
for i in range(n): C.cifrar_bloco(i, ks, 6)
print(f"\nVelocidade: {n/(time.perf_counter()-t):,.0f} blocos/s (Python puro, 6 rodadas)")
