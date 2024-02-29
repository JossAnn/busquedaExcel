import openpyxl
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import re

def leer_archivo_excel(nombre_archivo, criterio_busqueda):
    tree.delete(*tree.get_children())  # Limpiar tabla anterior
    try:
        libro = openpyxl.load_workbook(nombre_archivo)
        hoja_activa = libro.active
        for fila in hoja_activa.iter_rows():
            if any(criterio_busqueda in str(celda.value) for celda in fila):
                tree.insert("", tk.END, values=[celda.value for celda in fila])
    except FileNotFoundError:
        messagebox.showerror("Error", f"El archivo {nombre_archivo} no fue encontrado.")
    except Exception as e:
        messagebox.showerror("Error", f"Ocurrió un error: {str(e)}")

def iniciar_sesion():
    usuario = usuario_entry.get()
    contraseña = contraseña_entry.get()

    usuario_valido = validar_usuario(usuario)
    contraseña_valida = validar_contraseña(contraseña)

    if usuario_valido and not contraseña_valida:
        messagebox.showinfo("Información", "Inicio de sesión exitoso.")
        # Después de iniciar sesión exitosamente, habilitamos la entrada de búsqueda
        dominio_entry.config(state=tk.NORMAL)
        boton_buscar.config(state=tk.NORMAL)
    else:
        mensaje_error = "Inicio de sesión fallido. Problemas con los campos:\n"
        if not usuario_valido:
            mensaje_error += "- El nombre de usuario debe tener al menos 4 caracteres y no contener espacios.\n"
        if contraseña_valida:
            mensaje_error += "- Contraseña:\n"
            for mensaje in contraseña_valida:
                mensaje_error += f"  {mensaje}\n"
        messagebox.showwarning("Advertencia", mensaje_error)

def buscar():
    dominio_a_buscar = dominio_entry.get()
    if dominio_a_buscar:
        nombre_archivo = 'datospersonales.xlsx'
        leer_archivo_excel(nombre_archivo, dominio_a_buscar)
    else:
        messagebox.showwarning("Advertencia", "Ingrese un dominio válido.")

def validar_usuario(usuario):
    long = r'^\S{4,}$'
    if re.match(long, usuario):
        return True
    else:
        return False

def validar_contraseña(contraseña):
    long = r'^.{7,14}$'
    may = r'[A-Z]'
    minn = r'[a-z]'
    dig = r'\d'
    spchar = r'[^A-Za-z0-9\s]'

    mensajes = []

    if not re.match(long, contraseña):
        mensajes.append("Use entre 8 y 15 caracteres.")
    if not re.search(may, contraseña):
        mensajes.append("Use al menos una letra mayúscula.")
    if not re.search(minn, contraseña):
        mensajes.append("Use al menos una letra minúscula.")
    if not re.search(dig, contraseña):
        mensajes.append("Use al menos un dígito.")
    if not re.search(spchar, contraseña):
        mensajes.append("Use al menos un carácter especial.")
    if re.search(r'\s', contraseña):
        mensajes.append("No use espacios en blanco.")

    return mensajes

ventana = tk.Tk()
ventana.title("Inicio de Sesión y Búsqueda")

panel_inicio_sesion = ttk.Frame(ventana)
panel_inicio_sesion.grid(row=0, column=0, padx=10, pady=10)

etiqueta_usuario = ttk.Label(panel_inicio_sesion, text="Nombre de usuario:")
usuario_entry = ttk.Entry(panel_inicio_sesion)
etiqueta_contraseña = ttk.Label(panel_inicio_sesion, text="Contraseña:")
contraseña_entry = ttk.Entry(panel_inicio_sesion, show="*")
boton_iniciar_sesion = ttk.Button(panel_inicio_sesion, text="Iniciar Sesión", command=iniciar_sesion)

etiqueta_usuario.grid(row=0, column=0, padx=10, pady=10)
usuario_entry.grid(row=0, column=1, padx=10, pady=10)
etiqueta_contraseña.grid(row=1, column=0, padx=10, pady=10)
contraseña_entry.grid(row=1, column=1, padx=10, pady=10)
boton_iniciar_sesion.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

panel_busqueda = ttk.Frame(ventana)
panel_busqueda.grid(row=0, column=1, padx=10, pady=10)

etiqueta_busqueda = ttk.Label(panel_busqueda, text="Ingrese el dominio a buscar:")
dominio_entry = ttk.Entry(panel_busqueda, state=tk.DISABLED)
boton_buscar = ttk.Button(panel_busqueda, text="Buscar", command=buscar, state=tk.DISABLED)

etiqueta_busqueda.grid(row=0, column=0, padx=10, pady=10)
dominio_entry.grid(row=0, column=1, padx=10, pady=10)
boton_buscar.grid(row=0, column=2, padx=10, pady=10)

tree_frame = ttk.Frame(ventana)
tree_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

tree = ttk.Treeview(tree_frame, columns=("FOLIO", "NOMBRE", "CORREO", "TELEFONO"), show="headings")
tree.heading("FOLIO", text="FOLIO")
tree.heading("NOMBRE", text="NOMBRE")
tree.heading("CORREO", text="CORREO")
tree.heading("TELEFONO", text="TELEFONO")

tree.pack()
ventana.mainloop()
