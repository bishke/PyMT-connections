import routeros_api
from pristupni_parametri import server, admin, password

connection = routeros_api.RouterOsApiPool(server, username=admin, password=password,plaintext_login=True)

api = connection.get_api()

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

#stampaj listu
print("Aktivne IP")
for k in range(len(aktivne_ip)):
    
    print(aktivne_ip[k])
 

print("-------------------")
ukupno_ip = ['147.91.200.59:4001','147.91.200.59:4002','147.91.200.59:4003','147.91.200.59:4004','147.91.200.59:4005','147.91.200.59:4006','147.91.200.59:4007','147.91.200.59:4008','147.91.200.59:4009']


# Python code t get difference of two lists
# Using set()
def Diff(li1, li2):
	return (list(list(set(li1)-set(li2)) + list(set(li2)-set(li1))))

neaktivne_ip = Diff(ukupno_ip, aktivne_ip)
neaktivne_ip.sort()

print("Neaktivne IP")
for k in range(len(neaktivne_ip)):
    
    print(neaktivne_ip[k])
