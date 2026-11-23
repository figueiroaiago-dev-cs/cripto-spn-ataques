"""
Etapa 7 — Dashboard de segurança (Streamlit).
Rodar:  streamlit run dashboard.py
Ao vivo: laboratório da cifra e esteganografia. Lidos do disco: ataques e IA (com botão reprocessar).
"""
import io, json, os, subprocess, sys
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from PIL import Image

import cipher as C
import stego as S

BASE = Path(__file__).parent; RES = BASE / "resultados"; DADOS = BASE / "dados"
LARANJA, VERDE, CINZA = "#d25327", "#14a362", "#6e625c"
st.set_page_config(page_title="Projeto 1 · Segurança", layout="wide")
st.markdown("<style>html,body,[class*='css']{font-family:Arial,sans-serif}</style>", unsafe_allow_html=True)


def ler_json(nome):
    p = RES / f"{nome}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

def reprocessar(*cmd):
    with st.spinner("Reprocessando... pode levar alguns segundos"):
        r = subprocess.run([sys.executable, *cmd], cwd=BASE, capture_output=True, text=True)
    (st.success if r.returncode == 0 else st.error)(r.stdout[-1500:] or r.stderr[-1500:])
    st.cache_data.clear()

@st.cache_data
def carregar_eventos():
    return pd.read_parquet(DADOS / "eventos.parquet")

@st.cache_data
def carregar_janelas():
    return pd.read_parquet(DADOS / "janelas.parquet")


pagina = st.sidebar.radio("Página", ["Visão geral + alertas", "Laboratório da cifra",
                                     "Resultados dos ataques", "Esteganografia"])
st.sidebar.caption("Projeto 1 · Técnicas Avançadas de Criptografia · CESAR School")


# ======================= VISÃO GERAL =======================
if pagina == "Visão geral + alertas":
    st.title("Visão geral e alertas")
    if not (DADOS / "janelas.parquet").exists():
        st.warning("Rode `python eventos.py` e `python ia.py` primeiro."); st.stop()
    ev, jan, ia = carregar_eventos(), carregar_janelas(), ler_json("ia")
    alertas = jan[jan["alerta"]].copy()
    alertas["entidade"] = alertas["ip"].fillna(alertas["usuario"])
    alertas["motivo"] = np.select([alertas["alerta_ia"] & alertas["alerta_regra"], alertas["alerta_regra"]],
                                  ["IA + regra", "regra"], "IA")
    c = st.columns(4)
    c[0].metric("Eventos (30 dias)", f"{len(ev):,}".replace(",", "."))
    c[1].metric("Janelas analisadas", f"{len(jan):,}".replace(",", "."))
    c[2].metric("Alertas", len(alertas))
    c[3].metric("Falhas de login", int((ev["evento"] == "login_falha").sum()))

    por_hora = ev.set_index("ts").resample("h")["evento"].count().rename("eventos").reset_index()
    fig = px.area(por_hora, x="ts", y="eventos", color_discrete_sequence=[CINZA])
    marc = alertas.groupby("janela").size().rename("n").reset_index()
    fig.add_trace(go.Scatter(x=marc["janela"], y=por_hora.set_index("ts").reindex(marc["janela"])["eventos"],
                             mode="markers", marker=dict(color=LARANJA, size=10, symbol="x"), name="alerta"))
    fig.update_layout(height=300, margin=dict(l=0, r=0, t=30, b=0), title="Eventos por hora e alertas")
    st.plotly_chart(fig, width="stretch")

    st.subheader("Alertas (mais anômalos primeiro)")
    cols = ["visao", "entidade", "janela", "motivo", "score", "n_eventos", "falhas_login", "leituras",
            "hash_divergente", "estrangeiro", "hora"]
    st.dataframe(alertas.sort_values("score", ascending=False)[[c for c in cols if c in alertas]],
                 width="stretch", hide_index=True)

    with st.expander("Avaliação da IA com os rótulos dos ataques simulados"):
        for v in ("ip_x_hora", "usuario_x_hora"):
            st.markdown(f"**{v.replace('_x_', ' × ')}** · orçamento {ia['orcamento_alertas'][v]*100:.1f}% "
                        f"· average precision {ia[v]['average_precision_ia']:.2f}")
            st.dataframe(pd.DataFrame({k: ia[v][k] for k in ("alerta_regra", "alerta_ia", "alerta")}).T,
                         width="stretch")
            st.dataframe(pd.DataFrame(ia[v]["varredura_orcamento"]), width="stretch", hide_index=True)
    if st.button("Reprocessar eventos + IA"):
        reprocessar("eventos.py"); reprocessar("ia.py")


# ======================= LABORATÓRIO =======================
elif pagina == "Laboratório da cifra":
    st.title("Laboratório da cifra própria")
    st.caption("SPN · bloco de 64 bits · S-box fixa · camada P (transposição 8×8) · PBKDF2 + HMAC-SHA256 · CBC")
    a, b = st.columns(2)
    with a:
        texto = st.text_area("Mensagem", "Pagamento de R$ 3757,00 aprovado pelo financeiro.", key="lab_msg")
        senha = st.text_input("Senha", "recife2026", type="password", key="lab_senha")
        kb = st.select_slider("Tamanho da chave (bits)", C.KEY_SIZES, 128, key="lab_kb")
        R = st.slider("Rodadas", 1, 10, C.DEFAULT_ROUNDS, key="lab_r")
        if st.button("Cifrar"):
            st.session_state["pacote"] = C.cifrar_mensagem(texto, senha, kb, R)
    with b:
        if "pacote" in st.session_state:
            p = st.session_state["pacote"]
            st.markdown("**Pacote** `salt(16) | IV(8) | cifrado | tag(32)`")
            st.code(f"salt   {p[:16].hex()}\nIV     {p[16:24].hex()}\ncifra  {p[24:-32].hex()}\ntag    {p[-32:].hex()}")
            s2 = st.text_input("Senha para decifrar", "recife2026", type="password", key="lab_s2")
            try:
                st.success(C.decifrar_mensagem(p, s2, kb, R))
            except C.IntegridadeError as e:
                st.error(str(e))

    st.subheader("Efeito avalanche ao vivo (1 bloco)")
    xh = st.text_input("Bloco de entrada (16 dígitos hex = 64 bits)", "0123456789ABCDEF", key="lab_x")
    try:
        x = int(xh, 16) & (2**64 - 1)
    except ValueError:
        st.error("Use só dígitos hexadecimais (0-9, A-F)."); st.stop()
    bit = st.slider("Bit invertido", 0, 63, 0, key="lab_bit")
    ks = C.subchaves(b"chave-de-demo-16", R)
    y1, y2 = C.cifrar_bloco(int(x), ks, R), C.cifrar_bloco(int(x) ^ (1 << bit), ks, R)
    dif = bin(y1 ^ y2).count("1")
    st.code(f"saída A  {y1:064b}\nsaída B  {y2:064b}\ndiferença{''.join('^' if (y1 ^ y2) >> (63 - i) & 1 else ' ' for i in range(64))}")
    st.metric("Bits alterados", f"{dif}/64 ({100*dif/64:.1f}%)")
    d = ler_json("diferencial")
    if d:
        av = pd.DataFrame(d["avalanche_rodadas"]).melt("rodadas", var_name="alteração", value_name="%")
        fig = px.line(av, x="rodadas", y="%", color="alteração", markers=True,
                      color_discrete_sequence=[LARANJA, VERDE], title="Avalanche × rodadas (média de 1.500 amostras)")
        fig.add_hline(50, line_dash="dot", line_color=CINZA); st.plotly_chart(fig, width="stretch")


# ======================= ATAQUES =======================
elif pagina == "Resultados dos ataques":
    st.title("Resultados dos ataques")
    t1, t2, t3 = st.tabs(["Força bruta", "Diferencial", "Estatístico"])
    with t1:
        fb = ler_json("forca_bruta")
        if fb:
            c = st.columns(3)
            c[0].metric("Chaves/s (Python)", f"{fb['chave']['taxa_media']:,}".replace(",", "."))
            c[1].metric("Senha quebrada por dicionário", fb["dicionario"]["senha_alvo"] if fb["dicionario"]["achou"] else "não")
            c[2].metric("Tentativas até quebrar", fb["dicionario"]["tentativas"])
            st.dataframe(pd.DataFrame(fb["chave"]["projecao"])[["bits", "legivel"]].rename(
                columns={"legivel": "tempo médio de força bruta"}), hide_index=True)
            st.info(f"RockYou inteiro (14,3 mi senhas): {fb['dicionario']['rockyou_inteiro']} com PBKDF2 "
                    f"vs {fb['dicionario']['rockyou_sem_kdf']} sem KDF.")
            st.image(str(RES / "forca_bruta.png"))
        if st.button("Reprocessar força bruta"): reprocessar("ataques.py", "forca")
    with t2:
        d = ler_json("diferencial")
        if d:
            c = st.columns(3)
            c[0].metric("SAC médio (ideal 0,5)", d["sac"]["media"])
            c[1].metric("DDT máx. S-box própria", f"{d['ddt']['max_sbox_propria']}/256")
            c[2].metric("DDT máx. S-box AES", f"{d['ddt']['max_sbox_aes']}/256")
            M = np.load(RES / "sac.npy")
            st.plotly_chart(px.imshow(M, zmin=.3, zmax=.7, color_continuous_scale=[VERDE, "#ffffff", LARANJA],
                                      labels=dict(x="bit de saída", y="bit de entrada", color="P(muda)"),
                                      title="Matriz SAC (6 rodadas)"), width="stretch")
            st.markdown("**1 caractere alterado na mensagem**")
            st.dataframe(pd.DataFrame(d["mensagem_1_char"]).T, width="stretch")
        if st.button("Reprocessar diferencial"): reprocessar("ataques.py", "dif")
    with t3:
        e = ler_json("estatistico")
        if e:
            st.dataframe(pd.DataFrame(e).T.drop(columns="freq"), width="stretch")
            hist = pd.DataFrame({k: v["freq"] for k, v in e.items()}).reset_index(names="byte").melt("byte", var_name="dado", value_name="freq")
            st.plotly_chart(px.bar(hist, x="byte", y="freq", facet_col="dado", facet_col_wrap=2, height=500,
                                   color="dado", color_discrete_sequence=[LARANJA, CINZA, VERDE, "#2b6cb0"]),
                            width="stretch")
            st.image(str(RES / "imagem_ecb_cbc.png"), caption="ECB mantém o contorno; CBC vira ruído")
        if st.button("Reprocessar estatístico"): reprocessar("ataques.py", "est"); reprocessar("ataques.py", "img")


# ======================= ESTEGANOGRAFIA =======================
else:
    st.title("Esteganografia LSB")
    up = st.file_uploader("Imagem portadora (PNG/JPG). Sem upload, usa a portadora padrão.", ["png", "jpg", "jpeg"])
    img = np.array(Image.open(up).convert("RGB")) if up else np.array(Image.open(RES / "portadora_foto.png"))
    a, b = st.columns(2)
    with a:
        msg = st.text_area("Mensagem secreta", "Segue o código de acesso: 4821. Não compartilhe.", key="st_msg")
        senha = st.text_input("Senha", "recife2026", type="password", key="st_senha")
        bits = st.radio("Bits por canal", [1, 2], horizontal=True, key="st_bits")
        emb = st.radio("Posições", ["embaralhado", "sequencial"], horizontal=True, key="st_pos")
        st.caption(f"Capacidade: {S.capacidade(img, bits):,} bytes".replace(",", "."))
    if st.button("Embutir"):
        pac = C.cifrar_mensagem(msg, senha)
        st.session_state["stego"] = (S.embutir(img, pac, bits, senha if emb == "embaralhado" else None), bits, emb)
        st.session_state["stego_base"] = img
    if "stego" in st.session_state:
        st_img, bits_u, emb_u = st.session_state["stego"]; base = st.session_state["stego_base"]
        with b:
            st.metric("PSNR", f"{S.psnr(base, st_img):.2f} dB")
            buf = io.BytesIO(); Image.fromarray(st_img).save(buf, "PNG")
            st.download_button("Baixar imagem estego (PNG)", buf.getvalue(), "estego.png", "image/png")
        c = st.columns(4)
        c[0].image(base, caption="original"); c[1].image(st_img, caption="com mensagem")
        c[2].image((base[..., 0] & 1) * 255, caption="plano LSB original")
        c[3].image((st_img[..., 0] & 1) * 255, caption="plano LSB com mensagem")
        w0, w1 = S.westfeld(base), S.westfeld(st_img)
        df = pd.DataFrame({"% analisado": range(5, 101, 5), "original": w0, "com mensagem": w1})
        st.plotly_chart(px.line(df, x="% analisado", y=["original", "com mensagem"], range_y=[-.05, 1.05],
                                color_discrete_sequence=[CINZA, LARANJA], title="Qui-quadrado de Westfeld (p ≈ 1 = detectado)"),
                        width="stretch")

    st.subheader("Extrair")
    up2 = st.file_uploader("Imagem estego (PNG)", ["png"], key="up2")
    s2 = st.text_input("Senha", "recife2026", type="password", key="st_s2")
    bits2 = st.radio("Bits por canal ", [1, 2], horizontal=True, key="st_b2")
    emb2 = st.radio("Posições ", ["embaralhado", "sequencial"], horizontal=True, key="st_p2")
    if st.button("Extrair e decifrar"):
        alvo = np.array(Image.open(up2).convert("RGB")) if up2 else st.session_state.get("stego", (None,))[0]
        if alvo is None:
            st.warning("Envie uma imagem ou embuta uma mensagem primeiro.")
        else:
            try:
                st.success(C.decifrar_mensagem(S.extrair(alvo, bits2, s2 if emb2 == "embaralhado" else None), s2))
            except Exception as e:
                st.error(f"Não foi possível recuperar: {e}")
