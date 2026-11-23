"""
Parte 3 — Ataques contra a cifra própria (e AES-256 como referência).
Uso:  python ataques.py forca | dif | est | img | tudo
Saídas em ./resultados (JSON para o dashboard + PNG para relatório/slides).
"""
import json, math, os, random, sys, time
from collections import Counter
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import cipher as C
import corpus

OUT = Path(__file__).parent / "resultados"
OUT.mkdir(exist_ok=True)
LARANJA, VERDE, CINZA = "#d25327", "#14a362", "#6e625c"

def salvar(nome, dados):
    (OUT / f"{nome}.json").write_text(json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8")

def hd(a, b): return bin(a ^ b).count("1")


# =============== FORÇA BRUTA ===============
WORDLIST = (["123456", "senha", "password", "12345678", "qwerty", "abc123", "111111",
             "brasil", "flamengo", "corinthians", "palmeiras", "sport", "nautico", "santacruz",
             "recife", "iloveyou", "admin", "senha123", "mudar123", "cesar", "school",
             "dragon", "monkey", "jesus", "amor", "familia", "deus", "gabriel", "maria"]
            + [f"{w}{a}" for w in ("senha", "recife", "brasil", "sport", "cesar", "flamengo")
               for a in ("1", "12", "123", "2024", "2025", "2026", "@123", "!")])

def forca_bruta():
    res = {}
    # (a) busca exaustiva na chave reduzida, ataque de texto claro conhecido
    reais = []
    for k in (12, 16, 20):
        segredo = random.getrandbits(k)
        chave = segredo.to_bytes(4, "little")               # chave de 32 bits, só k bits desconhecidos
        P = 0x0123456789ABCDEF
        Cc = C.cifrar_bloco(P, C.subchaves(chave), C.DEFAULT_ROUNDS)
        t0 = time.perf_counter(); testadas = 0
        for g in range(1 << k):
            testadas += 1
            if C.cifrar_bloco(P, C.subchaves(g.to_bytes(4, "little")), C.DEFAULT_ROUNDS) == Cc:
                break
        dt = time.perf_counter() - t0
        reais.append({"bits": k, "testadas": testadas, "segundos": round(dt, 2),
                      "chaves_por_s": round(testadas / dt), "achou": g == segredo})
        print(f"  {k} bits: {testadas:,} chaves em {dt:.1f}s ({testadas/dt:,.0f}/s)")
    taxa = sum(r["chaves_por_s"] for r in reais) / len(reais)
    proj = []
    for bits in (16, 24, 32, 40, 56, 64, 128):
        s = (2 ** (bits - 1)) / taxa                         # caso médio
        proj.append({"bits": bits, "segundos_medio": s, "legivel": legivel(s)})
    res["chave"] = {"reais": reais, "taxa_media": round(taxa), "projecao": proj}

    # (b) dicionário sobre a senha (PBKDF2 100k) — o elo mais fraco
    alvo = "recife2026"
    pacote = C.cifrar_mensagem("Segue o código de acesso: 4821. Não compartilhe.", alvo)
    salt = pacote[:C.SALT_LEN]
    t0 = time.perf_counter(); achou = None; tent = 0
    for w in WORDLIST:
        tent += 1
        try:
            txt = C.decifrar_mensagem(pacote, w)
            if txt.isprintable(): achou = (w, txt); break
        except Exception:
            pass
    dt = time.perf_counter() - t0
    por_s = tent / dt
    # comparação: mesma senha sem KDF lento (1 iteração)
    t1 = time.perf_counter()
    for w in WORDLIST: C.derivar_chave(w, salt, 128, iters=1)
    por_s_sem_kdf = len(WORDLIST) / (time.perf_counter() - t1)
    rockyou = 14_344_391
    res["dicionario"] = {"senha_alvo": alvo, "tentativas": tent, "segundos": round(dt, 2),
                         "senhas_por_s": round(por_s, 1), "achou": bool(achou),
                         "texto_recuperado": achou[1] if achou else None,
                         "rockyou_inteiro": legivel(rockyou / por_s),
                         "rockyou_sem_kdf": legivel(rockyou / por_s_sem_kdf)}
    print(f"  dicionário: senha '{achou[0] if achou else '-'}' em {tent} tentativas, {dt:.1f}s")
    salvar("forca_bruta", res)

    fig, ax = plt.subplots(figsize=(7, 3.6))
    b = [p["bits"] for p in proj]; y = [p["segundos_medio"] for p in proj]
    ax.semilogy(b, y, "o-", color=LARANJA)
    for ref, nome in ((3600, "1 hora"), (3.15e7, "1 ano"), (4.35e17, "idade do universo")):
        ax.axhline(ref, color=CINZA, lw=.6, ls="--"); ax.text(b[0], ref * 1.6, nome, color=CINZA, fontsize=8)
    ax.set_xlabel("tamanho da chave (bits)"); ax.set_ylabel("tempo médio (s, log)")
    ax.set_title(f"Força bruta projetada a {taxa:,.0f} chaves/s (Python, 1 núcleo)")
    fig.tight_layout(); fig.savefig(OUT / "forca_bruta.png", dpi=150); plt.close(fig)

def legivel(s):
    for lim, nome, div in ((60, "s", 1), (3600, "min", 60), (86400, "h", 3600),
                           (3.15e7, "dias", 86400), (float("inf"), "anos", 3.15e7)):
        if s < lim: return f"{s/div:,.1f} {nome}"


# =============== DIFERENCIAL ===============
def aes_sbox():
    def mul(a, b):
        p = 0
        while b:
            if b & 1: p ^= a
            a <<= 1
            if a & 0x100: a ^= 0x11B
            b >>= 1
        return p
    inv = [0] * 256
    for a in range(1, 256):
        inv[a] = next(b for b in range(1, 256) if mul(a, b) == 1)
    s = []
    for a in range(256):
        x = inv[a]; y = x
        for i in range(1, 5): y ^= ((x << i) | (x >> (8 - i))) & 0xFF
        s.append(y ^ 0x63)
    return s

def ddt_max(sbox):
    m = 0; hist = Counter()
    for dx in range(1, 256):
        cnt = Counter(sbox[x] ^ sbox[x ^ dx] for x in range(256))
        hist.update(cnt.values()); m = max(m, max(cnt.values()))
    return m, dict(sorted(hist.items()))

def diferencial():
    rng = random.Random(7); res = {}
    # avalanche x rodadas
    av = []
    for R in range(1, 11):
        tp = tk = 0; N = 1500
        for _ in range(N):
            k = os.urandom(16); ks = C.subchaves(k, R); x = rng.getrandbits(64)
            tp += hd(C.cifrar_bloco(x, ks, R), C.cifrar_bloco(x ^ (1 << rng.randrange(64)), ks, R))
            k2 = bytearray(k); k2[rng.randrange(16)] ^= 1 << rng.randrange(8)
            tk += hd(C.cifrar_bloco(x, ks, R), C.cifrar_bloco(x, C.subchaves(bytes(k2), R), R))
        av.append({"rodadas": R, "texto_pct": round(100 * tp / N / 64, 2), "chave_pct": round(100 * tk / N / 64, 2)})
    res["avalanche_rodadas"] = av

    # SAC 64x64 (6 rodadas)
    N = 150; M = np.zeros((64, 64))
    for i in range(64):
        for _ in range(N):
            ks = C.subchaves(os.urandom(16)); x = rng.getrandbits(64)
            d = C.cifrar_bloco(x, ks, 6) ^ C.cifrar_bloco(x ^ (1 << i), ks, 6)
            M[i] += [(d >> j) & 1 for j in range(64)]
    M /= N
    res["sac"] = {"media": round(float(M.mean()), 4), "min": round(float(M.min()), 3),
                  "max": round(float(M.max()), 3), "desvio_medio_de_0_5": round(float(abs(M - .5).mean()), 4)}
    np.save(OUT / "sac.npy", M)

    # DDT
    m_prop, h_prop = ddt_max(C.SBOX); m_aes, _ = ddt_max(aes_sbox())
    res["ddt"] = {"max_sbox_propria": m_prop, "max_sbox_aes": m_aes,
                  "prob_melhor_diferencial_propria": f"{m_prop}/256",
                  "prob_melhor_diferencial_aes": f"{m_aes}/256", "histograma_propria": h_prop}

    # 1 caractere alterado numa mensagem: ECB x CBC x AES-GCM (IV/nonce repetidos de propósito)
    msg1 = "Pagamento de R$ 3757,00 aprovado pelo financeiro.".encode()
    msg2 = "Pagamento de R$ 3758,00 aprovado pelo financeiro.".encode()
    k = os.urandom(16); iv = os.urandom(8); kaes = AESGCM.generate_key(256); n = os.urandom(12)
    def comp(a, b):
        bits = sum(hd(x, y) for x, y in zip(a, b))
        return {"bytes_diferentes": sum(x != y for x, y in zip(a, b)), "total_bytes": len(a),
                "bits_diferentes_pct": round(100 * bits / (8 * len(a)), 1)}
    res["mensagem_1_char"] = {
        "ECB": comp(C.cifrar_bytes(msg1, k, "ECB"), C.cifrar_bytes(msg2, k, "ECB")),
        "CBC_mesmo_IV": comp(C.cifrar_bytes(msg1, k, "CBC", iv=iv), C.cifrar_bytes(msg2, k, "CBC", iv=iv)),
        "CBC_IV_novo": comp(C.cifrar_bytes(msg1, k, "CBC"), C.cifrar_bytes(msg2, k, "CBC")),
        "AES_GCM_mesmo_nonce": comp(AESGCM(kaes).encrypt(n, msg1, None), AESGCM(kaes).encrypt(n, msg2, None)),
    }
    salvar("diferencial", res)
    print("  avalanche 6 rodadas:", av[5]); print("  SAC:", res["sac"]); print("  DDT:", res["ddt"]["max_sbox_propria"], "vs AES", m_aes)
    for kk, v in res["mensagem_1_char"].items(): print("  ", kk, v)

    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.plot([a["rodadas"] for a in av], [a["texto_pct"] for a in av], "o-", color=LARANJA, label="1 bit do texto")
    ax.plot([a["rodadas"] for a in av], [a["chave_pct"] for a in av], "s--", color=VERDE, label="1 bit da chave")
    ax.axhline(50, color=CINZA, lw=.6, ls=":"); ax.set_ylim(0, 60)
    ax.set_xlabel("rodadas"); ax.set_ylabel("% de bits alterados na saída"); ax.legend()
    ax.set_title("Efeito avalanche × número de rodadas")
    fig.tight_layout(); fig.savefig(OUT / "avalanche_rodadas.png", dpi=150); plt.close(fig)
    fig, ax = plt.subplots(figsize=(5, 4.4))
    im = ax.imshow(M, vmin=0.3, vmax=0.7, cmap="RdYlGn_r" if False else "coolwarm")
    fig.colorbar(im, label="P(bit de saída muda)"); ax.set_xlabel("bit de saída"); ax.set_ylabel("bit de entrada invertido")
    ax.set_title("SAC — 6 rodadas (ideal: tudo 0,5)")
    fig.tight_layout(); fig.savefig(OUT / "sac_heatmap.png", dpi=150); plt.close(fig)


# =============== ESTATÍSTICO ===============
def metricas(b: bytes):
    from scipy.stats import chisquare
    arr = np.frombuffer(b, dtype=np.uint8)
    freq = np.bincount(arr, minlength=256)
    p = freq[freq > 0] / len(arr)
    chi = chisquare(freq)
    corr = float(np.corrcoef(arr[:-1], arr[1:])[0, 1])
    blocos = [b[i:i + 8] for i in range(0, len(b) - 7, 8)]
    return {"bytes": len(b), "entropia_bits_por_byte": round(float(-(p * np.log2(p)).sum()), 4),
            "qui2": round(float(chi.statistic), 1), "p_valor": round(float(chi.pvalue), 4),
            "uniforme_5pct": bool(chi.pvalue > 0.05), "correlacao_vizinhos": round(corr, 4),
            "blocos_8B_repetidos_pct": round(100 * (1 - len(set(blocos)) / len(blocos)), 2),
            "freq": freq.tolist()}

def estatistico():
    claro = "\n".join(corpus.gerar(3000)).encode()
    k = os.urandom(16); kaes = AESGCM.generate_key(256)
    # mensagens cifradas uma a uma (como no chat), concatenadas
    ecb = b"".join(C.cifrar_bytes(m.encode(), k, "ECB") for m in corpus.gerar(3000))
    cbc = b"".join(C.cifrar_bytes(m.encode(), k, "CBC") for m in corpus.gerar(3000))
    aes = b"".join(AESGCM(kaes).encrypt(os.urandom(12), m.encode(), None) for m in corpus.gerar(3000))
    res = {nome: metricas(d) for nome, d in
           (("texto_claro", claro), ("propria_ECB", ecb), ("propria_CBC", cbc), ("AES_256_GCM", aes))}
    salvar("estatistico", res)
    for n, r in res.items():
        print(f"  {n:12s} H={r['entropia_bits_por_byte']:.3f}  qui2={r['qui2']:>10}  p={r['p_valor']:.3f}  "
              f"corr={r['correlacao_vizinhos']:+.3f}  blocos rep={r['blocos_8B_repetidos_pct']}%")
    fig, axs = plt.subplots(1, 4, figsize=(12, 2.8), sharey=False)
    for ax, (n, r) in zip(axs, res.items()):
        ax.bar(range(256), r["freq"], width=1, color=LARANJA if n == "texto_claro" else VERDE)
        ax.set_title(f"{n}\nH={r['entropia_bits_por_byte']:.2f} bits/byte", fontsize=9); ax.set_xticks([0, 128, 255])
    fig.tight_layout(); fig.savefig(OUT / "histogramas.png", dpi=150); plt.close(fig)


# =============== IMAGEM ECB x CBC ===============
def imagem():
    from PIL import Image, ImageDraw, ImageFont
    W, H = 320, 200
    img = Image.new("RGB", (W, H), (255, 255, 255)); d = ImageDraw.Draw(img)
    d.ellipse((20, 30, 150, 170), fill=(210, 83, 39)); d.rectangle((170, 40, 300, 160), fill=(20, 163, 98))
    d.polygon([(235, 55), (285, 145), (185, 145)], fill=(255, 255, 255))
    raw = img.tobytes(); k = os.urandom(16)
    ecb = C.cifrar_bytes(raw, k, "ECB", padding=False)
    cbc = C.cifrar_bytes(raw, k, "CBC", padding=False)[8:]
    ims = [img, Image.frombytes("RGB", (W, H), ecb), Image.frombytes("RGB", (W, H), cbc)]
    fig, axs = plt.subplots(1, 3, figsize=(10, 2.6))
    for ax, im, t in zip(axs, ims, ("original", "cifra própria — ECB", "cifra própria — CBC")):
        ax.imshow(im); ax.set_title(t); ax.axis("off")
    fig.tight_layout(); fig.savefig(OUT / "imagem_ecb_cbc.png", dpi=150); plt.close(fig)
    salvar("imagem", {"ECB": metricas(ecb) | {"freq": None}, "CBC": metricas(cbc) | {"freq": None}})
    print("  imagem salva")


if __name__ == "__main__":
    alvo = sys.argv[1] if len(sys.argv) > 1 else "tudo"
    for nome, f in (("forca", forca_bruta), ("dif", diferencial), ("est", estatistico), ("img", imagem)):
        if alvo in (nome, "tudo"):
            print(f"[{nome}]"); f()
