import pyshark
import netifaces
import tkinter as tk
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
from scapy.all import get_if_list
import ipaddress


class pckt(object):
    def __init__(self,time_stamp:str='',ipsrc:str='',ipdst:str='',srcport:str='',dstport:str='',transport_layer:str='',highest_layer:str=''):
        self_time_stamp
        pass


intF = '\\Device\\NPF_{DDC3B35C-5B45-4B28-A4AE-7009317ED8B6}'
capture = pyshark.LiveCapture(interface=intF)

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

def aa(ip, puerto):
    amenaza = Amenaza(ip=ip, puerto=puerto)
    session.add(amenaza)
    session.commit()

def es_amenaza_conocida(ip, puerto):
    amenaza = session.query(Amenaza).filter_by(ip=ip, puerto=puerto).first()
    return amenaza is not None


def is_private_ip(ip_address)->bool:

    ip =ipaddress.ip_address(ip_address)
    return ip.is_private

def filter  (packet:capture):

    if packet.trasnport_layer == 'TCP' or packet.transport_layer == 'UDP':
        pass


def printpack():
    for packet in capture.sniff_continuously():
        print(packet)
        lista_alertas.insert(tk.END, f"Paquete capturado: {packet}") 
         


def crear_gui():
    global lista_alertas  
    
    ventana = tk.Tk()
    ventana.title("IDS")

    etiqueta = tk.Label(ventana, text="Datos recibidos", font=("Arial", 14))
    etiqueta.pack(pady=10)

    lista_alertas = tk.Listbox(ventana, width=80, height=20)
    lista_alertas.pack(padx=10, pady=10)

    
    boton_iniciar = tk.Button(ventana, text="Iniciar IDS", command=printpack)
    boton_iniciar.pack(pady=10)

    ventana.mainloop()

aa('192.168.1.15',22)
aa('203.0.113.45',80)
aa('198.51.100.23',443)
aa('203.0.113.55',3306)
aa('198.51.100.78',3389)



crear_gui()