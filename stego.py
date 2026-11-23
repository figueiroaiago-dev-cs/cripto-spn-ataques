"""
Esteganografia LSB: esconde o pacote cifrado (salt|IV|cifrado|tag) em PNG.
  - bits por canal: 1 (padrão do sistema) ou 2 (teste comparativo)
  - posições: sequenciais ou embaralhadas por uma semente derivada da senha
  - cabeçalho de 32 bits com o tamanho do payload
Uso: python stego.py [caminho_da_foto.png]   -> roda a análise e salva em resultados/
"""
import hashlib, json, sys
from pathlib import Path

import numpy as np
from PIL import Image

import cipher as C
import corpus

OUT = Path(__file__).parent / "resultados"; OUT.mkdir(exist_ok=True)


def _ordem(n_slots: int, senha: str | None):
    if senha is None:
        return np.arange(n_slots)
    seed = int.from_bytes(hashlib.sha256(("stego:" + senha).encode()).digest()[:8], "little")
    return np.random.default_rng(seed).permutation(n_slots)

def capacidade(img: np.ndarray, bits: int = 1) -> int:
    return img.size * bits // 8 - 4                     # bytes úteis (menos o cabeçalho)

def embutir(img: np.ndarray, payload: bytes, bits: int = 1, senha: str | None = None) -> np.ndarray:
    dados = len(payload).to_bytes(4, "big") + payload
    if len(dados) * 8 > img.size * bits:
        raise ValueError(f"payload grande demais: capacidade {capacidade(img, bits)} bytes")
    flat = img.reshape(-1).copy()
    bitstream = np.unpackbits(np.frombuffer(dados, np.uint8))
    if len(bitstream) % bits:
        bitstream = np.concatenate([bitstream, np.zeros(bits - len(bitstream) % bits, np.uint8)])
    simbolos = bitstream.reshape(-1, bits) @ (1 << np.arange(bits - 1, -1, -1))   # grupos de 'bits'
    pos = _ordem(flat.size, senha)[:len(simbolos)]
    mascara = np.uint8(0xFF ^ ((1 << bits) - 1))
    flat[pos] = (flat[pos] & mascara) | simbolos.astype(np.uint8)
    return flat.reshape(img.shape)

def extrair(img: np.ndarray, bits: int = 1, senha: str | None = None) -> bytes:
    flat = img.reshape(-1); ordem = _ordem(flat.size, senha)
    def ler(n_bytes, inicio_simb=0):
        n_simb = -(-n_bytes * 8 // bits)
        v = flat[ordem[inicio_simb:inicio_simb + n_simb]] & ((1 << bits) - 1)
        bs = ((v[:, None] >> np.arange(bits - 1, -1, -1)) & 1).astype(np.uint8).reshape(-1)
        return np.packbits(bs[:n_bytes * 8]).tobytes()
    # cabeçalho e payload são lidos como um único fluxo
    tam = int.from_bytes(ler(4), "big")
    return ler(4 + tam)[4:]


# ---------- métricas ----------
def psnr(a, b):
    mse = np.mean((a.astype(float) - b.astype(float)) ** 2)
    return float("inf") if mse == 0 else 10 * np.log10(255 ** 2 / mse)

def westfeld(img: np.ndarray, passos: int = 20):
    """Ataque qui-quadrado (Westfeld & Pfitzmann): p ~ 1 => embedding detectado."""
    from scipy.stats import chi2
    flat = img.reshape(-1); out = []
    for i in range(1, passos + 1):
        h = np.bincount(flat[: flat.size * i // passos], minlength=256).astype(float)
        par, impar = h[0::2], h[1::2]; esp = (par + impar) / 2
        ok = esp > 4
        est = float(((par[ok] - esp[ok]) ** 2 / esp[ok]).sum())
        gl = int(ok.sum()) - 1
        out.append(round(float(1 - chi2.cdf(est, gl)), 4) if gl >= 1 else None)
    return out


# ---------- portadoras ----------
def portadora_lisa(W=512, H=512):
    img = Image.new("RGB", (W, H), (245, 245, 245))
    from PIL import ImageDraw
    d = ImageDraw.Draw(img)
    d.ellipse((40, 60, 260, 280), fill=(210, 83, 39)); d.rectangle((290, 80, 480, 300), fill=(20, 163, 98))
    d.rectangle((60, 340, 460, 460), fill=(35, 28, 25))
    return np.array(img)

def portadora_foto(caminho=None, W=512, H=512):
    if caminho and Path(caminho).exists():
        return np.array(Image.open(caminho).convert("RGB").resize((W, H))), Path(caminho).name
    # substituto: gradientes suaves + ruído de sensor (até você colocar uma foto real)
    rng = np.random.default_rng(3)
    y, x = np.mgrid[0:H, 0:W] / max(W, H)
    base = np.stack([140 + 80 * np.sin(3 * x + 2 * y), 120 + 70 * np.cos(4 * y - x), 100 + 60 * np.sin(5 * x * y)], -1)
    return np.clip(base + rng.normal(0, 6, base.shape), 0, 255).astype(np.uint8), "foto_sintetica (substituto)"


def analisar(caminho_foto=None):
    senha = "recife2026"
    payload = b"".join(C.cifrar_mensagem(m, senha) for m in corpus.gerar(400))   # conversa cifrada
    foto, nome_foto = portadora_foto(caminho_foto)
    res = {"payload_bytes": len(payload), "portadoras": {}}
    for nome, img in (("foto", foto), ("lisa", portadora_lisa())):
        r = {"arquivo": nome_foto if nome == "foto" else "imagem lisa sintética",
             "capacidade_1bit": capacidade(img, 1), "capacidade_2bit": capacidade(img, 2),
             "original_westfeld": westfeld(img), "variantes": {}}
        for bits in (1, 2):
            for modo, s in (("sequencial", None), ("embaralhado", senha)):
                st = embutir(img, payload, bits, s)
                ok = extrair(st, bits, s) == payload
                r["variantes"][f"{bits}bit_{modo}"] = {
                    "ocupacao_pct": round(100 * len(payload) / capacidade(img, bits), 1),
                    "psnr_db": round(psnr(img, st), 2), "recuperou": ok,
                    "westfeld": westfeld(st)}
                if bits == 1 and modo == "embaralhado":
                    Image.fromarray(st).save(OUT / f"stego_{nome}.png")
                    # recuperação completa: imagem -> pacotes -> texto
                    rec = extrair(np.array(Image.open(OUT / f"stego_{nome}.png")), 1, senha)
                    r["recuperacao_png"] = rec == payload
        Image.fromarray(img).save(OUT / f"portadora_{nome}.png")
        res["portadoras"][nome] = r
    # adulteração: inverte 1 LSB da imagem estego numa posição usada => HMAC acusa
    st = np.array(Image.open(OUT / "stego_foto.png")); pos = _ordem(st.size, senha)[200]
    st.reshape(-1)[pos] ^= 1
    rec = extrair(st, 1, senha); pac = rec[:len(C.cifrar_mensagem("x", "y"))]
    falhas = 0
    tamanhos = [len(C.cifrar_mensagem(m, senha)) for m in corpus.gerar(400)]
    i = 0
    for t in tamanhos:
        try: C.decifrar_mensagem(rec[i:i + t], senha)
        except C.IntegridadeError: falhas += 1
        i += t
    res["adulteracao_1_bit"] = {"mensagens": len(tamanhos), "rejeitadas_pelo_hmac": falhas}
    (OUT / "stego.json").write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    return res


def figuras():
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    senha = "recife2026"
    payload = b"".join(C.cifrar_mensagem(m, senha) for m in corpus.gerar(400))
    fig, axs = plt.subplots(2, 3, figsize=(9, 6.2))
    for lin, nome in enumerate(("foto", "lisa")):
        img = np.array(Image.open(OUT / f"portadora_{nome}.png"))
        for col, (tit, im) in enumerate((("original", img),
                                         ("1 bit sequencial", embutir(img, payload, 1, None)),
                                         ("1 bit embaralhado", embutir(img, payload, 1, senha)))):
            axs[lin, col].imshow((im[..., 0] & 1) * 255, cmap="gray", interpolation="nearest")
            axs[lin, col].set_title(f"{nome}: {tit}", fontsize=9); axs[lin, col].axis("off")
    fig.suptitle("Ataque visual: plano LSB do canal vermelho", fontsize=11)
    fig.tight_layout(); fig.savefig(OUT / "stego_plano_lsb.png", dpi=150); plt.close(fig)
    r = json.loads((OUT / "stego.json").read_text(encoding="utf-8"))["portadoras"]["foto"]
    fig, ax = plt.subplots(figsize=(7, 3.4)); xs = [5 * i for i in range(1, 21)]
    ax.plot(xs, r["original_westfeld"], color="#6e625c", label="original")
    for k, c in (("1bit_sequencial", "#d25327"), ("1bit_embaralhado", "#14a362")):
        ax.plot(xs, r["variantes"][k]["westfeld"], color=c, label=k.replace("_", " "))
    ax.set_xlabel("% da imagem analisada"); ax.set_ylabel("p (1 = embedding detectado)"); ax.set_ylim(-.05, 1.05)
    ax.set_title("Qui-quadrado de Westfeld — foto, payload 43% da capacidade"); ax.legend()
    fig.tight_layout(); fig.savefig(OUT / "stego_westfeld.png", dpi=150); plt.close(fig)


if __name__ == "__main__":
    r = analisar(sys.argv[1] if len(sys.argv) > 1 else None)
    print("payload:", r["payload_bytes"], "bytes")
    for n, p in r["portadoras"].items():
        print(f"\n[{n}] {p['arquivo']}  cap 1bit={p['capacidade_1bit']:,}B  original Westfeld (100%)={p['original_westfeld'][-1]}")
        for k, v in p["variantes"].items():
            w = v["westfeld"]
            print(f"  {k:16s} ocup={v['ocupacao_pct']:5.1f}%  PSNR={v['psnr_db']:.2f} dB  ok={v['recuperou']}  "
                  f"Westfeld {w}")
        print("  recuperação via PNG:", p["recuperacao_png"])
    print("\nadulteração:", r["adulteracao_1_bit"])
    figuras()
