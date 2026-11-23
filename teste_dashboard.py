from streamlit.testing.v1 import AppTest
for pg in ["Visão geral + alertas", "Laboratório da cifra", "Resultados dos ataques", "Esteganografia"]:
    at = AppTest.from_file("dashboard.py", default_timeout=120); at.run()
    at.sidebar.radio[0].set_value(pg).run()
    if pg == "Laboratório da cifra":
        at.button[0].click().run()
        print(pg, "-> decifrado:", [s.value for s in at.success][:1])
    if pg == "Esteganografia":
        at.button[0].click().run(); at.button[1].click().run()
        print(pg, "-> extraído:", [s.value for s in at.success][:1])
    print(pg, "exceções:", [e.value for e in at.exception] or "nenhuma")
