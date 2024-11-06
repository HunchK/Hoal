import pyshark
import netifaces
import tkinter as tk
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
import threading


engine = create_engine('sqlite:///amenazas.db')
Base = declarative_base()


class Amenaza(Base):
    __tablename__ = 'enemigos'
    id = Column(Integer, primary_key=True)
    ip = Column(String)
    puerto = Column(Integer)


Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()


def agregar_amenaza(ip, puerto):
    amenaza = Amenaza(ip=ip, puerto=puerto)
    session.add(amenaza)
    session.commit()


def es_amenaza_conocida(ip, puerto):
    amenaza = session.query(Amenaza).filter_by(ip=ip, puerto=puerto).first()
    return amenaza is not None


def capturar_paquetes(lista_alertas):
    captura = pyshark.LiveCapture(interface='eth0') 

    for paquete in captura.sniff_continuously():
        if 'IP' in paquete and 'TCP' in paquete:
            ip_origen = paquete.ip.src
            puerto_destino = int(paquete.tcp.dstport)


            alerta = f"[INFO] Capturado: {ip_origen}:{puerto_destino}"
            lista_alertas.insert(tk.END, alerta)


            if es_amenaza_conocida(ip_origen, puerto_destino):
             
                lista_alertas.itemconfig(tk.END, {'bg': 'red'})
                lista_alertas.insert(tk.END, f"[ALERTA] Tráfico sospechoso detectado desde {ip_origen} al puerto {puerto_destino}")


def crear_gui(): 
    ventana = tk.Tk()
    ventana.title("IDS")

    etiqueta = tk.Label(ventana, text="Alertas de tráfico sospechoso:", font=("Arial", 14))
    etiqueta.pack(pady=10)

    lista_alertas = tk.Listbox(ventana, width=80, height=20)
    lista_alertas.pack(padx=10, pady=10)

    boton_iniciar = tk.Button(ventana, text="Iniciar IDS", command=lambda: capturar_paquetes(lista_alertas))
    boton_iniciar.pack(pady=10)

    ventana.mainloop()

# Agregar amenazas de ejemplo a la base de datos
# agregar_amenaza("192.168.1.10", 23)  # Puedes usar esta línea para agregar una amenaza de prueba

crear_gui()
