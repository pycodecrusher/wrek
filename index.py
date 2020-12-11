'''
(var_0.a0xf):build a basic structure
(var_0.a1xd):creating a 4 fuction
(var_0.a2xs):Adding a socket lib & change function input sys
(ver.253a)  :Update to input ip shown

Auther:PycodeCrusher@lk

'''
import json
import nmap3
import socket

nmap = nmap3.Nmap()

def top_port_scan():
    ip=input("Enter your target:")
    ip=socket.gethostbyname(ip)
    print("[+]Set] target ip: "+str (ip))
    results = nmap.scan_top_ports(ip)
    var = results[ip]
    a=len(var)
    print(" ")
    for i in range(0,a):
        print("Port id:"+var[i].get('portid')+" "+"State: "+var[i].get('state'))
    print(" ")

def sub_domain_scan():
    ip=input("Enter your target:")
    ip=socket.gethostbyname(ip)
    print("[+]Set] target ip: "+str (ip))
    results = nmap.nmap_dns_brute_script(ip)
    a=len(results)
    print("Genataring reports:(0x1jo35gu.13) ")
    for i in range(0,a):
        print("hostname: "+results[i]['hostname']+"\taddress: "+results[i]['address'])
    print(" ")
    
def dns_leak_test():
    ip=input("Enter your target:")
    ip=socket.gethostbyname(ip)
    print("[+]Set] target ip: "+str (ip))
    results = nmap.nmap_os_detection(ip)
    print(" ")
    print("name: "+results[0]['name'])
    print("accuracy: "+results[0]['accuracy'])
    print("cpe: "+results[0]['cpe'])
    print(" ")
    
def scan_fin():                                #this function need to modified
    ip=input("Enter your target:")
    ip=socket.gethostbyname(ip)
    print("[+]Set] target ip: "+str (ip))
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_fin_scan(ip)
    print(result)
    
def scan_idle():                                #this function need to modified
    ip=input("Enter your target:")
    ip=socket.gethostbyname(ip)
    print("[Set] target ip: "+str (ip))
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_idle_scan(ip)
    print(result)

def scan_ping():                                
    ip=input("Enter your target:")
    ip=socket.gethostbyname(ip)
    print("[+]Set] target ip: "+str (ip))
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_ping_scan(ip)
    print(" ")
    print("[*]scanning you entered ip")
    print("[>]Target ip state :"+result[0]['state'])
    print(" ")

def scan_syn():                                #this function need to modified
    ip=input("Enter your target:")
    ip=socket.gethostbyname(ip)
    print("[Set] target ip: "+str (ip))   #update ver.253a
    nmap = nmap3.NmapScanTechniques()
    result = nmap.nmap_syn_scan(ip)
    a= len(result[ip])
    #print(result[ip][0])                 #for see what things in dic
    print("Syn-ack sscan")
    for i in range(0,a):
        print(result[ip][i]['protocol']+": Port "+result[ip][i]['portid']+" "+result[ip][i]['state']+" ttl: "+result[ip][i]['reason_ttl'])
    print("[=]Scan Successful!")
    
print(" ")
print("================================================================================")
print(" ")
print("\t"+"\t"+"\t"+"[00]: check target state (up/down)")
print("\t"+"\t"+"\t"+"[01]: traditional methods")
print("\t"+"\t"+"\t"+"[06]: new methods")
print("\t"+"\t"+"\t"+"[04]: list scan")
print("\t"+"\t"+"\t"+"[03]: check update & version ")
print("\t"+"\t"+"\t"+"[03]: Help")
print("\t"+"\t"+"\t"+"[99]: Exit")
print(" ")
print("================================================================================")
   
    
while True == True:
    choos=str(input("[+]wrek|:"))
    
    if choos == "04":
        print("================================================================================")
        print(" ")
        print("\t"+"\t"+"\t"+"[0 ]: scan-syn")
        print("\t"+"\t"+"\t"+"[1 ]: top-port-scan")
        print("\t"+"\t"+"\t"+"[2 ]: sub domain-scan")
        print("\t"+"\t"+"\t"+"[3 ]: os detection-scan ")
        print("\t"+"\t"+"\t"+"[99]: back")
        print(" ")
        print("================================================================================")
        
        while True == True:
            chos=str(input("[+]wrek|:"))
            if chos == "0":
                scan_syn()
            elif chos == "1":
                top_port_scan()
            elif chos == "2":
                sub_domain_scan()
            elif chos == "3":
                 dns_leak_test()
            else:
                break
    #top_port_scan(ip)
    if choos == "1":
        pass
    elif choos == "4":
        scan_fin()
    elif choos == "5":
        scan_idle()
    elif choos == "00":
        scan_ping()  
    elif choos == "99":
        break
    