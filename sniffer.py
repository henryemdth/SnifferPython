import socket
import struct
import textwrap

TAB_1 = '\t|-'
TAB_2 = '\t: '



def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

    
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]



conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
while True:
    print('')
    raw_data, addr = conn.recvfrom(65565)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

    print('Ethernet Header')
    print(TAB_1 + 'Destination Address'+TAB_2+dest_mac)
    print(TAB_1 + 'Destination Address'+TAB_2+src_mac)
    print(TAB_1 + 'Protocol\t'+TAB_2+str(eth_proto))
    tcpData = data
    if eth_proto == 8:
        
       
        unpackedData = struct.unpack('!BBHHHBBH4s4s', tcpData[:20])        
        version_IHL = unpackedData[0]        
        version = version_IHL >> 4        
        IHL = version_IHL & 0xF   
        print('IP Header')
        print(TAB_1+"IP Version\t",TAB_2,version)
        print(TAB_1+"IP Header Length",TAB_2, IHL,'DWORDS',str(IHL*32//8) ,'Bytes')
        print(TAB_1+"Type Of Service",TAB_2,unpackedData[1])
        print(TAB_1+"IP Total Lenght",TAB_2,unpackedData[2],'Bytes(Size of Packet)')
        print(TAB_1+"Identification",TAB_2,str(unpackedData[3]))
        print(TAB_1+"TTL\t\t",TAB_2,str(unpackedData[5]))
        print(TAB_1+"Protocol\t",TAB_2,str(unpackedData[6]))
        print(TAB_1+"Checksum\t",TAB_2,unpackedData[7])
        print(TAB_1+"Destination IP",TAB_2,str(socket.inet_ntoa(unpackedData[9])))
        proto=str(unpackedData[6])
        
        
        
        # ICMP
        if proto == '1':
            icmp_type, code, checksum, data = icmp_packet(data)
            print('ICMP Packet')
            print(TAB_1+"Type\t",TAB_2,icmp_type)
            print(TAB_1+"Code\t",TAB_2,code)
            print(TAB_1+"Checksum\t",TAB_2,checksum)

        # TCP
        elif proto == '6':
            iph_l=IHL * 4            
            tcp_header = tcpData[iph_l:iph_l+20]            
            tcph = struct.unpack('!HHLLBBHHH' , tcp_header)            
            tcph_l =tcph[4] >> 4   
            
            print("TCP Header")    
            print(TAB_1,"Source Port",TAB_2,tcph[0])
            print(TAB_1,"Destination Port",TAB_2,tcph[1])
            print(TAB_1,"Sequence Number",TAB_2,tcph[2])
            print(TAB_1,"Acknowledge Number",TAB_2,tcph[3])
            print(TAB_1,"Header Number",TAB_2,'DWORDS or ',str(tcph_l*32//8) ,'bytes')
    
            tcp_f=tcph[5] 
            t32=0 
            t16=0
            t8=0
            t4=0
            t2=0
            t1=0
            if(tcp_f & 32!=0): 
                t23=1         
            print(TAB_1,"Urgent Flag\t",TAB_2,t32)
            if(tcp_f & 16!=0): 
                t16=1 
            print(TAB_1,"Acknowledge Flag",TAB_2,t16)
            if(tcp_f & 8!=0): 
                t8=1 
            print(TAB_1,"Push Flag\t",TAB_2,t8)
            if(tcp_f & 4!=0): 
                t4=1 
            print(TAB_1,"Reset Flag\t",TAB_2,t4)
            if(tcp_f & 2!=0): 
                t2=1 
            print(TAB_1,"Syncronise Flag",TAB_2,t2)
            if(tcp_f & 1!=0): 
                t1=1 
            print(TAB_1,"Finish Flag\t",TAB_2,t1)          

            print(TAB_1,"Window",tcph[6])
            print(TAB_1,"Checksum:",tcph[7])
            print(TAB_1,"Urgent Pointer:",tcph[8])           
            
        # UDP
        elif proto == '17':
            src_port, dest_port, length, data = udp_seg(data)
            print('UDP Segment:')
            print(TAB_1,'Source Port',TAB_2,src_port)
            print(TAB_1,'Destination Port',TAB_2,dest_port)
            print(TAB_1,'Length Port',TAB_2,length)

       
