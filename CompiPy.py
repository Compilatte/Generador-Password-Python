#!/usr/bin/env python3

# --- Importaciones de estándar de Python ---
import tkinter as tk #módulo base de tkinter (GUI Nativa)
from tkinter import ttk, messagebox, simpledialog #submódulos/controles avanzados y cuadros de diálogos
import secrets, string, json, os, base64 # Utilidades: aleatorios criptográficos, conjunto de caractéres, JSON
# cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC #derivar llaves a partir de una contraseña
from cryptography.hazmat.primitives import hashes #algoritmos de hash (SHA256)
from cryptography.fernet import Fernet #cifrado simétrico (alto nivel) con autentificación

VAULT_FILE = "vault.enc" #archivo donde se guarda el json con contraseñas
SALT_FILE  = "salt.bin" #archivo donde se guarda el salt usado en la derivación de llave
KDF_ITERS  = 200_000  # iteraciones de PBKDF2 es mas lento pero más seguro

# ---------- Sección Helpers Criptográficos (funciones) ----------
def derive_key(master: str, salt: bytes) -> bytes:
    """
    Función: deriva una llave simétrica a partir de la contraseña maestra
    devuelve la llave codificada en base64
    """
    kdf = PBKDF2HMAC( #creamos un objeto tipo KDF (key derivation function)
        algorithm=hashes.SHA256(), 
        length=32,
        salt=salt,
        iterations=KDF_ITERS, #número de iteraciones resistencia a fuerza bruta
    )
    return base64.urlsafe_b64encode(kdf.derive(master.encode("utf-8")))

def enc_json(obj: dict, key: bytes) -> bytes:
    """
    Función para encriptado
    """
    return Fernet(key).encrypt(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

def dec_json(token: bytes, key: bytes) -> dict:
    """
    Función para desencriptado
    """
    return json.loads(Fernet(key).decrypt(token).decode("utf-8"))

def load_vault(key: bytes) -> dict:
    """
    Función carga el vault desde disco, lo descifra con key 
    Si no existe el archivo, regresa el dict vacío y lo guarda en mi VAULT.
    """
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        token = f.read()
    return dec_json(token, key)

def save_vault(obj: dict, key: bytes) -> None:
    """
    Función para cifrar el dict obj y guardarlo en VAULT FILE.
    """
    with open(VAULT_FILE, "wb") as f:
        f.write(enc_json(obj, key))

# ---------- Password helpers ----------
def generar_password(longitud: int, mayus: bool, numeros: bool, simbolos: bool) -> str:
    """
    Función para generación de contraseña segura
    """
    chars = string.ascii_lowercase #la base es minúsculas 
    if mayus:
        chars += string.ascii_uppercase #si se selecciona genera mayúsculas
    if numeros:
        chars += string.digits #si se selecciona genera números
    if simbolos:
        chars += string.punctuation #si se selecciona genera símbolos
    if not chars:
        raise ValueError("Selecciona al menos un tipo de caracteres.")

    # Garantiza al menos un char de cada tipo marcado
    req = []
    if mayus:   req.append(secrets.choice(string.ascii_uppercase))
    if numeros: req.append(secrets.choice(string.digits))
    if simbolos:req.append(secrets.choice(string.punctuation))
    if longitud < len(req):
        raise ValueError("Longitud menor que los tipos seleccionados.")

    #Rellena el resto con caracteres aleatorios de las opciones marcadas
    rest = [secrets.choice(chars) for _ in range(longitud - len(req))] #Lo repite tantas veces como falten caracteres para completar la contraseña (longitud - len(req)).
    pwd_list = req + rest

    for i in range(len(pwd_list) - 1, 0, -1): # range recorre la lista de atrás hacia adelante
        j = secrets.randbelow(i + 1) #genera un número aleatorio entre 0 y i (incluido).
        pwd_list[i], pwd_list[j] = pwd_list[j], pwd_list[i] #intercambia los elementos en las posiciones
    return "".join(pwd_list)

def strength(pwd: str):
    """
    Función que calcula una 'Fuerza' de contraseña simple y etiqueta como débil, media o fuerte
    NOTA: métrica didáctica, no estandar de seguridad real.
    """
    if not pwd:
        return 0, "—"
    #Cuenta cuantos tipos de caracteres hay
    kinds = sum([
        any(c.islower() for c in pwd),
        any(c.isupper() for c in pwd),
        any(c.isdigit() for c in pwd),
        any(c in string.punctuation for c in pwd),
    ])
    #calcula la fuerza dependiendo del score generado
    score = min(len(pwd), 20) * 2 + kinds * 15   # métrica simple para demo
    #si tiene más de 20 caracteres, lo limita a 20 (para no dar puntos infinitos). Luego lo multiplica por 2 → así obtiene hasta 40 puntos máximos por longitud
    score = min(score, 100) #Asegura que el resultado final no pase de 100 puntos.
    label = "Débil" if score < 50 else ("Media" if score < 75 else "Fuerte")
    return score, label

# --------------- App -----------------
class App(tk.Tk): #App es una subclase de tkinter
    def __init__(self):
        """
        Método constructor inicializa ventana, desbloquea/crea vault y construye la ventana principal
        """
        super().__init__() #estamos diciendo usa el constructor original de tkinter para construir la ventana principal
        self.title("CompiPy - Generador de Contraseñas")
        self.geometry("760x440")
        self.minsize(720, 440)

        # --- Vault bootstrap (crear o desbloquear)
        self.key = None
        if not os.path.exists(SALT_FILE):
            self._create_master()
        else:
            self._unlock_master()
        if self.key is None:
            messagebox.showinfo("Adiós", "No se desbloqueó el vault.")
            self.destroy()
            return
        #carga del vault
        try:
            self.vault = load_vault(self.key)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el vault: {e}")
            self.vault = {}

        # --- Variables de estado para la UI
        self.var_length = tk.IntVar(value=12)
        self.var_upper = tk.BooleanVar(value=True)
        self.var_digits = tk.BooleanVar(value=True)
        self.var_symbols = tk.BooleanVar(value=True)
        self.var_show = tk.BooleanVar(value=False)
        self.var_pwd = tk.StringVar(value="")
        self.var_site = tk.StringVar(value="")
        self.var_user = tk.StringVar(value="")

        #Construye la UI
        self._build_ui()

        # Conecta el callback del slider HASTA EL FINAL (opción B)
        self.scale.configure(command=self._on_len)

        # Estado inicial
        self._update_strength()
        self._refresh_list()

    # ----- Master / Vault -----
    def _create_master(self):
        """
        Método: crea una nueva master key y genera una vault vacía
        """
        pw = simpledialog.askstring("Crear master", "Crea tu contraseña maestra:", show="*")
        if not pw:
            self.key = None
            return
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        self.key = derive_key(pw, salt)
        save_vault({}, self.key)
        messagebox.showinfo("OK", "Vault creado. ¡No olvides tu master!")

    def _unlock_master(self):
        """
        Método: solicita la master key y abre su vault si la contraseña es correcta.
        """
        pw = simpledialog.askstring("Desbloquear", "Contraseña maestra:", show="*")
        if not pw:
            self.key = None
            return
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        try:
            key = derive_key(pw, salt)
            _ = load_vault(key)  # valida
            self.key = key
        except Exception:
            messagebox.showerror("Error", "Master incorrecta.")
            self.key = None

    def _build_ui(self):
        """
        Método crea los widgets, los agrupa y define los botones
        """

        pad = {"padx":12, "pady": 8} #padding común, 12 pixeles horizontal y 8 pixeles vertical
        left = ttk.Frame(self) #Panel izquierdo
        left.pack(side="left", fill="both", expand=True, **pad)
        right = ttk.Frame(self, width=280) #Panel derecho
        right.pack(side="right", fill="y", padx=(0,12), pady=12)

        #Opciones
        fo = ttk.Labelframe(left, text="Opciones")
        fo.pack(fill="x")
        r1 = ttk.Frame(fo) #Fila 1 Longitud y el slider
        r1.pack(fill="x", padx=8, pady=6)
        ttk.Label(r1, text="Longitud:").pack(side="left")

        #Creamos el scale
        self.scale = ttk.Scale(r1, from_=6, to=64, orient="horizontal")
        self.scale.set(self.var_length.get())
        self.scale.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Label(r1, textvariable=self.var_length, width=3).pack(side="left")

        r2 = ttk.Frame(fo) #Fila 2 Checkbox de los tipos de caracteres
        r2.pack(fill="x", padx=8, pady=2)
        for txt, var in[("Mayúsculas", self.var_upper),
                        ("Números", self.var_digits),
                        ("Símbolos", self.var_symbols)]:
            ttk.Checkbutton(
                r2, text=txt, variable=var, command=self._update_strength
            ).pack(side="left", padx=(0, 12))
            
        #Resultado y Campos
        fr = ttk.LabelFrame(left, text="Resultado y Guardar")
        fr.pack(fill="x", pady=(8, 0))
        row = ttk.Frame(fr)
        row.pack(fill="x", padx=8, pady=6)
        self.entry = ttk.Entry(row, textvariable=self.var_pwd, show="*", font=("Consolas", 12))
        #Campo de password por defecto muestra ******
        self.entry.pack(side="left", fill="x", expand=True)
        ttk.Checkbutton(row, text="Mostrar", variable=self.var_show,
                        command=self._toggle_show).pack(side="left", padx=8)
        ttk.Button(row, text="Copiar", command=self._copy_pwd).pack(side="left")

        iu = ttk.Frame(fr) #fila del sitio y usuario
        iu.pack(fill="x", padx=8, pady=4)
        ttk.Label(iu, text="Sitio:").pack(side="left")
        ttk.Entry(iu, textvariable=self.var_site).pack(side="left", fill="x", expand=True, padx=(6, 12))
        ttk.Label(iu, text="Usuario:").pack(side="left")
        ttk.Entry(iu, textvariable=self.var_user, width=22).pack(side="left", padx=(6, 0))

        # identificador de fuerza
        sr = ttk.Frame(fr)
        sr.pack(fill="x", padx=8, pady=(2, 8))
        ttk.Label(sr, text="Fuerza:").pack(side="left")
        self.pb = ttk.Progressbar(sr, mode="determinate", length=240)
        self.pb.pack(side="left", padx=8)
        self.lbls = ttk.Label(sr, text="—")
        self.lbls.pack(side="left")

        # Botones para las acciones
        fa = ttk.Frame(left)
        fa.pack(fill="x", pady=8)
        ttk.Button(fa, text="Generar", command=self._gen).pack(side="left")
        ttk.Button(fa, text="Guardar en Vault", command=self._save_entry).pack(side="left", padx=6)
        ttk.Button(fa, text="Limpiar", command=self._clear).pack(side="left", padx=6)
        ttk.Button(fa, text="Salir", command=self.destroy).pack(side="right")

        ttk.Label(left, text="No olvides suscribirte a Compilatte!",
                  foreground="#666").pack(anchor="w", padx=6, pady=(0, 6))

        # Lista del vault (panel derecho)
        ttk.Label(right, text="Vault (sitios)").pack(anchor="w")
        self.listbox = tk.Listbox(right, height=18)
        self.listbox.pack(fill="both", expand=True, pady=(6, 6))
        self.listbox.bind("<<ListboxSelect>>", self._on_select)

        #botones de gestión del item seleccionado
        vb = ttk.Frame(right)
        vb.pack(fill="x")
        ttk.Button(vb, text="Mostrar/ocultar", command=self._toggle_selected).pack(side="left")
        ttk.Button(vb, text="Copiar contraseña", command=self._copy_selected).pack(side="left", padx=6)
        ttk.Button(vb, text="Eliminar", command=self._delete_selected).pack(side="right")

    # ----- Handlers -----
    def _on_len(self, *_):
        """
        Handler: se llama cuando mueves el slider de longitud.
        Actualiza var_length y la fuerza
        """
        self.var_length.set(int(self.scale.get()))
        self._update_strength()
        
    def _toggle_show(self):
        """
        Alterna mostrar/ocultar los caracteres de la contraseña
        """
        self.entry.configure(show="" if self.var_show.get() else "*")

    def _copy_pwd(self):
        """
        Copia la contraseña en caso de que no esté vacío
        """
        pwd = self.var_pwd.get()
        if not pwd:
            messagebox.showwarning("Nada", "Genera una contraseña")
            return
        self.clipboard_clear
        self.clipboard_append(pwd)
        messagebox.showinfo("Copiado", "Contraseña Copiada")

    def _gen(self):
        """
        Handler para crear nueva contraseña segun las opciones seleccionadas
        """
        try:
            pwd = generar_password(
                self.var_length.get(),
                self.var_upper.get(),
                self.var_digits.get(),
                self.var_symbols.get()
            )
            self.var_pwd.set(pwd)
            self.entry.selection_range(0, tk.END)
            self.entry.focus_set()
            self._update_strength()
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def _clear(self):
        """
        Handler: limpia campos de sitio usuario y refrezca la barra de fuerza
        """
        self.var_pwd.set("")
        self.var_site.set("")
        self.var_user.set("")
        self._update_strength()
        self.entry.focus_set()

    def _update_strength(self):
        """
        Método: recalcula fuerza de la contraseña actual y refrezca la barra
        """
        sc, lb = strength(self.var_pwd.get())
        self.pb["value"] = sc #VALUE CON MINUSCULA MINUSCULA MINUSCULA
        self.lbls.config(text=f"{lb} ({sc}%)") #actualiza el label dependiendo del strength y dice si es fuerte debil o media

    # ----- Vault list -----
    def _refresh_list(self):
        """
        Método: pone la lista de los sitios ordenados con case sensitive
        """
        self.listbox.delete(0, tk.END)
        for site in sorted(self.vault.keys(), key=str.lower):
            user = self.vault[site].get("user", "")
            self.listbox.insert(tk.END, f"{site} — {user}")

    def _on_select(self, _):
        """ 
        Handler: cuando seleccionas un sitio en la lista carga sitio y usuario
        (no se muestra la contraseña por defecto por seguridad).
        """
        sel = self.listbox.curselection()
        if not sel:
            return
        site = self.listbox.get(sel[0]).split(" — ")[0]
        data = self.vault.get(site, {})
        self.var_site.set(site)
        self.var_user.set(data.get("user", ""))
        self.var_pwd.set("")     # no mostramos automáticamente
        self._update_strength()

    def _toggle_selected(self):
        """
        Alterna ocultar/mostrar la contraseña del sitio seleccionado
        """
        sel = self.listbox.curselection()
        if not sel:
            return messagebox.showwarning("Nada", "Selecciona un sitio.")
        site = self.listbox.get(sel[0]).split(" — ")[0]
        pwd = self.vault.get(site, {}).get("password", "")
        if not pwd:
            return messagebox.showinfo("Vacío", "No hay contraseña guardada.")
        # toggle valida si está en mostrar u ocultar y la muestra o no
        self.var_pwd.set("" if self.var_pwd.get() == pwd else pwd)
        self._update_strength()

    def _copy_selected(self):
        """
        Copia al portapapeles la contraseña del sitio seleccionado si es que existe.
        """
        sel = self.listbox.curselection()
        if not sel:
            return messagebox.showwarning("Nada", "Selecciona un sitio.")
        site = self.listbox.get(sel[0]).split(" — ")[0]
        pwd = self.vault.get(site, {}).get("password", "")
        if not pwd:
            return messagebox.showinfo("Vacío", "No hay contraseña guardada.")
        self.clipboard_clear()
        self.clipboard_append(pwd)
        messagebox.showinfo("Copiado", f"Contraseña de {site} copiada.")

    def _delete_selected(self):
        """
        Elimina el registro seleccionado.
        """
        sel = self.listbox.curselection()
        if not sel:
            return messagebox.showwarning("Nada", "Selecciona un sitio.")
        site = self.listbox.get(sel[0]).split(" — ")[0]
        if messagebox.askyesno("Confirmar", f"¿Eliminar {site}?"):
            self.vault.pop(site, None)
            save_vault(self.vault, self.key)
            self._refresh_list()
            messagebox.showinfo("Listo", "Eliminado.")

    def _save_entry(self):
        """
        Guarda o actualiza el sitio y su contraseña
        """
        site = self.var_site.get().strip()
        user = self.var_user.get().strip()
        pwd  = self.var_pwd.get().strip()
        if not site or not pwd:
            return messagebox.showwarning("Faltan datos", "Escribe sitio y genera/pega contraseña.")
        self.vault[site] = {"user": user, "password": pwd}
        save_vault(self.vault, self.key)
        self._refresh_list()
        messagebox.showinfo("Guardado", f"{site} guardado.")

#--------------- Punto de entrada a la App ------------------
if __name__ == "__main__":
    App().mainloop()