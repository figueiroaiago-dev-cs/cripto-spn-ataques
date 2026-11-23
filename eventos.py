"""
Etapa 5 — Big Data: geração híbrida do log de eventos + armazenamento Parquet/DuckDB.

1) Amostra REAL: operações executadas de verdade (login PBKDF2, cifrar/decifrar com
   HMAC, extrair estego, verificar hash SHA-256 de arquivo) -> durações medidas.
2) SIMULAÇÃO em escala (~50 mil eventos, 30 dias, 16 usuários) usando as durações reais.
3) Ataques injetados (rótulo só para avaliação, NUNCA usado no treino da IA):
   forca_bruta, alteracao_arquivo, acesso_atipico (+ rajada de leitura/exfiltração).
Saída: dados/eventos.parquet   |   Uso: python eventos.py
"""
import hashlib, os, time
from datetime import datetime, timedelta
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd

import cipher as C
import corpus

BASE = Path(__file__).parent
DADOS = BASE / "dados"; DADOS.mkdir(exist_ok=True)
rng = np.random.default_rng(2026)
INICIO = datetime(2026, 10, 1)
DIAS = 30
USUARIOS = [u for u in corpus.USUARIOS]
IP_CASA = {u: [f"177.{rng.integers(10, 250)}.{rng.integers(0, 255)}.{rng.integers(1, 254)}"
               for _ in range(rng.integers(1, 3))] for u in USUARIOS}
ARQUIVOS = [f"conversas/{u}_stego.png" for u in USUARIOS]

COLS = ["ts", "usuario", "ip", "pais", "evento", "recurso", "bytes", "duracao_ms", "sucesso",
        "origem", "rotulo_ataque"]


# ---------------- 1) amostra real ----------------
def amostra_real():
    linhas = []; senhas = {u: f"{u}#Senha2026" for u in USUARIOS}
    cad = {}
    for u in USUARIOS:                                      # cadastro: salt + hash PBKDF2
        s = os.urandom(16); cad[u] = (s, hashlib.pbkdf2_hmac("sha256", senhas[u].encode(), s, C.PBKDF2_ITERS))
    def login(u, senha):
        t = time.perf_counter()
        ok = hashlib.pbkdf2_hmac("sha256", senha.encode(), cad[u][0], C.PBKDF2_ITERS) == cad[u][1]
        return ok, (time.perf_counter() - t) * 1000
    ts = INICIO
    for i, m in enumerate(corpus.gerar(60, seed=9)):
        u = USUARIOS[i % len(USUARIOS)]; ip = IP_CASA[u][0]; ts += timedelta(minutes=7)
        errou = i % 10 == 0
        ok, d = login(u, senhas[u] + ("x" if errou else ""))
        linhas.append([ts, u, ip, "BR", "login_ok" if ok else "login_falha", "auth", 0, d, ok, "real", "normal"])
        if not ok: continue
        t = time.perf_counter(); pac = C.cifrar_mensagem(m, senhas[u]); d = (time.perf_counter() - t) * 1000
        linhas.append([ts + timedelta(seconds=5), u, ip, "BR", "msg_cifrar", "chat", len(pac), d, True, "real", "normal"])
        adulterar = i % 15 == 0
        if adulterar: pac = pac[:-1] + bytes([pac[-1] ^ 1])
        t = time.perf_counter()
        try: C.decifrar_mensagem(pac, senhas[u]); ok2 = True
        except C.IntegridadeError: ok2 = False
        d = (time.perf_counter() - t) * 1000
        linhas.append([ts + timedelta(seconds=9), USUARIOS[(i + 1) % 16], IP_CASA[USUARIOS[(i + 1) % 16]][0], "BR",
                       "msg_decifrar_ok" if ok2 else "msg_decifrar_falha", "chat", len(pac), d, ok2, "real", "normal"])
    # hash de arquivo real: imagem estego da Etapa 4
    png = BASE / "resultados" / "stego_foto.png"
    if png.exists():
        dado = png.read_bytes()
        for j in range(20):
            t = time.perf_counter(); hashlib.sha256(dado).hexdigest(); d = (time.perf_counter() - t) * 1000
            linhas.append([INICIO + timedelta(hours=j), USUARIOS[j % 16], IP_CASA[USUARIOS[j % 16]][0], "BR",
                           "arquivo_hash_ok", ARQUIVOS[j % 16], len(dado), d, True, "real", "normal"])
    df = pd.DataFrame(linhas, columns=COLS)
    return df


# ---------------- 2) simulação normal ----------------
def simular_normal(dur: dict, alvo=48_000):
    tipos = ["login_ok", "msg_cifrar", "msg_decifrar_ok", "stego_embutir", "stego_extrair",
             "arquivo_escrita", "arquivo_hash_ok", "login_falha", "msg_decifrar_falha", "logout"]
    pesos = np.array([.10, .30, .32, .05, .06, .04, .07, .02, .006, .034]); pesos /= pesos.sum()
    por_usuario_dia = alvo / (len(USUARIOS) * DIAS * 0.8)
    linhas = []
    for dia in range(DIAS):
        data = INICIO + timedelta(days=dia); fds = data.weekday() >= 5
        for u in USUARIOS:
            n = rng.poisson(por_usuario_dia * (0.25 if fds else 1.0))
            horas = np.clip(rng.normal(13, 2.6, n), 7, 21)
            for h, ev in zip(np.sort(horas), rng.choice(tipos, n, p=pesos)):
                ts = data + timedelta(hours=float(h))
                rec = "auth" if ev.startswith("log") else ("chat" if ev.startswith("msg") else ARQUIVOS[USUARIOS.index(u)])
                fonte = dur.get(ev, dur["msg_cifrar"])
                linhas.append([ts, u, rng.choice(IP_CASA[u]), "BR", ev, rec,
                               int(rng.normal(180, 60)) if rec == "chat" else (0 if rec == "auth" else int(rng.normal(9e5, 1e5))),
                               float(rng.choice(fonte)) * rng.uniform(.9, 1.1),
                               not ev.endswith("falha"), "simulado", "normal"])
    return pd.DataFrame(linhas, columns=COLS)


# ---------------- 3) ataques injetados ----------------
def ip_ext(): return f"{rng.choice([45, 91, 103, 185, 194])}.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 254)}"

def ataques(dur):
    L = []
    def add(ts, u, ip, pais, ev, rec, b, ok, rot):
        L.append([ts, u, ip, pais, ev, rec, b, float(rng.choice(dur.get(ev, dur["login_ok"]))), ok, "simulado", rot])
    # força bruta direcionada (3) + credential stuffing (1)
    for dia, alvo, n, sucesso in ((4, "marina", 420, False), (12, "hugo", 650, True), (21, "carla", 300, False)):
        ip = ip_ext(); pais = rng.choice(["RU", "CN", "NL"]); t = INICIO + timedelta(days=dia, hours=float(rng.uniform(1, 5)))
        for k in range(n):
            t += timedelta(seconds=float(rng.exponential(1.8)))
            add(t, alvo, ip, pais, "login_falha", "auth", 0, False, "forca_bruta")
        if sucesso: add(t + timedelta(seconds=2), alvo, ip, pais, "login_ok", "auth", 0, True, "forca_bruta")
    ip = ip_ext(); t = INICIO + timedelta(days=17, hours=3)
    for k in range(240):
        t += timedelta(seconds=float(rng.exponential(3)))
        add(t, USUARIOS[k % 16], ip, "US", "login_falha", "auth", 0, False, "forca_bruta")
    # alteração inesperada de arquivo: hash diverge sem escrita legítima antes
    for dia, u in ((8, "felipe"), (15, "julia"), (26, "otavio")):
        t = INICIO + timedelta(days=dia, hours=float(rng.uniform(0, 24)))
        for k in range(int(rng.integers(1, 4))):
            add(t + timedelta(minutes=10 * k), u, rng.choice(IP_CASA[u]), "BR", "arquivo_hash_divergente",
                ARQUIVOS[USUARIOS.index(u)], int(rng.normal(9e5, 1e5)), False, "alteracao_arquivo")
            add(t + timedelta(minutes=10 * k, seconds=3), u, rng.choice(IP_CASA[u]), "BR", "msg_decifrar_falha",
                "chat", 0, False, "alteracao_arquivo")
    # acesso atípico + rajada de leitura (exfiltração): madrugada, país novo, credencial válida
    for dia, u in ((10, "bruno"), (23, "paula")):
        ip = ip_ext(); pais = rng.choice(["RO", "VN"]); t = INICIO + timedelta(days=dia, hours=float(rng.uniform(2, 4)))
        add(t, u, ip, pais, "login_ok", "auth", 0, True, "acesso_atipico")
        for k in range(int(rng.integers(250, 400))):
            t += timedelta(seconds=float(rng.exponential(2.5)))
            ev = rng.choice(["msg_decifrar_ok", "stego_extrair"], p=[.7, .3])
            add(t, u, ip, pais, ev, "chat" if ev.startswith("msg") else rng.choice(ARQUIVOS),
                int(rng.normal(180, 60)) if ev.startswith("msg") else int(rng.normal(9e5, 1e5)), True, "acesso_atipico")
    return pd.DataFrame(L, columns=COLS)


def main():
    t0 = time.perf_counter()
    real = amostra_real()
    dur = {ev: g["duracao_ms"].to_numpy() for ev, g in real.groupby("evento")}
    dur.setdefault("stego_embutir", dur["msg_cifrar"] * 3); dur.setdefault("stego_extrair", dur["msg_cifrar"] * 2)
    dur.setdefault("arquivo_escrita", dur.get("arquivo_hash_ok", dur["msg_cifrar"]))
    dur.setdefault("arquivo_hash_divergente", dur.get("arquivo_hash_ok", dur["msg_cifrar"]))
    dur.setdefault("logout", np.array([1.0]))
    df = pd.concat([real, simular_normal(dur), ataques(dur)], ignore_index=True).sort_values("ts", ignore_index=True)
    df["bytes"] = df["bytes"].clip(lower=0).astype("int64"); df["duracao_ms"] = df["duracao_ms"].round(2)
    df.to_parquet(DADOS / "eventos.parquet", index=False)
    print(f"{len(df):,} eventos em {time.perf_counter()-t0:.1f}s  ->  dados/eventos.parquet "
          f"({(DADOS/'eventos.parquet').stat().st_size/1e6:.2f} MB)")

    con = duckdb.connect(); con.execute(f"CREATE VIEW ev AS SELECT * FROM '{(DADOS/'eventos.parquet').as_posix()}'")
    print(con.sql("SELECT origem, rotulo_ataque, count(*) n FROM ev GROUP BY ALL ORDER BY n DESC").df().to_string(index=False))
    print("\nTop IPs por falhas de login em 1 hora:")
    print(con.sql("""SELECT ip, pais, date_trunc('hour', ts) hora, count(*) falhas, count(DISTINCT usuario) usuarios
                     FROM ev WHERE evento='login_falha' GROUP BY ALL ORDER BY falhas DESC LIMIT 5""").df().to_string(index=False))

if __name__ == "__main__":
    main()
