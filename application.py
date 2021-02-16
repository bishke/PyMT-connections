from flask import Flask, render_template
import routeros_api
from pristupni_parametri import server, admin, password


application = Flask(__name__)

ukupno_ip = ['147.91.200.59:4001','147.91.200.59:4002','147.91.200.59:4003','147.91.200.59:4004','147.91.200.59:4005','147.91.200.59:4006','147.91.200.59:4007','147.91.200.59:4008','147.91.200.59:4009']


def connect(server,admin,password):
    connection = routeros_api.RouterOsApiPool(server, username=admin, password=password,plaintext_login=True)
    return connection

def daj_aktivne_ip():
    povezi = connect(server,admin,password)
    api = povezi.get_api()

    #pokupi sve podatke iz komande: ip firewall connection print
    raw_mt_output_connections = api.get_binary_resource('/ip/firewall/connection').call('print')

    #opseg za koji se vrsi pretraga aktivnih konekcija
    ip_opseg=b'147.91.200.59:400'
    aktivne_ip =[]


    #prolaz kroz svaki zapis u firewall tabeli koja nadgleda trenutne konekcije
    for i in range(len(raw_mt_output_connections)):
        #uslov da postoji tcp-state kljuc i da je on 'established'
        if 'tcp-state' in raw_mt_output_connections[i] and raw_mt_output_connections[i]['tcp-state']==b'established' and raw_mt_output_connections[i]['orig-rate']>b"0":
            #uslov da adresa pocinje sa ip_opseg jer se racunari za umetnike nalaze u tom IP opsegu
            if raw_mt_output_connections[i]['dst-address'].startswith(ip_opseg):
                #konverzija iz byte-string u u-string
                uString = raw_mt_output_connections[i]['dst-address'].decode('utf-8')
                #dodaj svaki zapis su listu
                aktivne_ip.append(uString)
    
    #sortiranje liste
    aktivne_ip.sort()
    return aktivne_ip
 
def daj_neaktivne_ip():
    aktivne_ip=daj_aktivne_ip()
    neaktivne_ip = Diff(ukupno_ip, aktivne_ip)
    neaktivne_ip.sort()
    return neaktivne_ip

def Diff(li1, li2):
	return (list(list(set(li1)-set(li2)) + list(set(li2)-set(li1))))






@application.route("/")
def home():
    aktivne_ip=daj_aktivne_ip()
    neaktivne_ip=daj_neaktivne_ip()
    status = {}
    for i in range(len(ukupno_ip)):
        for k in range(len(neaktivne_ip)):
            if ukupno_ip[i]==neaktivne_ip[k]:
                status[ukupno_ip[i]]='neaktivna'
    for a in range(len(ukupno_ip)):
        for b in range(len(aktivne_ip)):
            if ukupno_ip[a]==aktivne_ip[b]:
                status[ukupno_ip[a]]='aktivna'    
                
    print(status)
    return render_template('home.html',status=status)


if __name__=='__main__':
    application.run(debug=True)