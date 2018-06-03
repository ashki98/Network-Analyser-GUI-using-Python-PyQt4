from __future__ import division
import dpkt                  #importing the dpkt package for parsing the pcanpng file
import socket                  #importing socket package
import sys
import os
from PyQt4 import QtGui, QtCore
import time


try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(668, 467)
        MainWindow.setMaximumSize(QtCore.QSize(751, 467))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("modem.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow.setWindowIcon(icon)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.pushButton = QtGui.QPushButton(self.centralwidget)
        self.pushButton.setMaximumSize(QtCore.QSize(651, 81))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8("google.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pushButton.setIcon(icon1)
        self.pushButton.setObjectName(_fromUtf8("pushButton"))
        self.verticalLayout.addWidget(self.pushButton)
        self.pushButton_2 = QtGui.QPushButton(self.centralwidget)
        self.pushButton_2.setMaximumSize(QtCore.QSize(651, 111))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8("wifi.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pushButton_2.setIcon(icon2)
        self.pushButton_2.setObjectName(_fromUtf8("pushButton_2"))
        self.verticalLayout.addWidget(self.pushButton_2)
        self.progressBar = QtGui.QProgressBar(self.centralwidget)
        self.progressBar.setEnabled(False)
        self.progressBar.setAccessibleName(_fromUtf8(""))
        self.progressBar.setAccessibleDescription(_fromUtf8(""))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setTextVisible(True)
        self.progressBar.setObjectName(_fromUtf8("progressBar"))
        self.verticalLayout.addWidget(self.progressBar)
        self.listWidget = QtGui.QListWidget(self.centralwidget)
        self.listWidget.setMaximumSize(QtCore.QSize(651, 192))
        self.listWidget.setObjectName(_fromUtf8("listWidget"))
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        self.verticalLayout.addWidget(self.listWidget)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtGui.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 668, 21))
        self.menubar.setObjectName(_fromUtf8("menubar"))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "Analysis of Wi-Fi Network", None))
        self.pushButton.setText(_translate("MainWindow", "Send Request to Google", None))
        self.pushButton.clicked.connect(self.send_req)
        self.pushButton_2.setText(_translate("MainWindow", "Capture on Wi-Fi and Analyse the requests", None))
        self.pushButton_2.clicked.connect(self.capture_wifi)
        __sortingEnabled = self.listWidget.isSortingEnabled()
        self.listWidget.setSortingEnabled(False)
        item = self.listWidget.item(0)
        item.setText(_translate("MainWindow", "Percentage of ARP:", None))
        item = self.listWidget.item(1)
        item.setText(_translate("MainWindow", "Percentage of HTTPS:", None))
        item = self.listWidget.item(2)
        item.setText(_translate("MainWindow", "Percentage of HTTP:", None))
        item = self.listWidget.item(3)
        item.setText(_translate("MainWindow", "Percentage of DNS:", None))
        item = self.listWidget.item(4)
        item.setText(_translate("MainWindow", "Percentage of other TCP:", None))
        item = self.listWidget.item(5)
        item.setText(_translate("MainWindow", "Percentage of other UDP:", None))
        item = self.listWidget.item(6)
        item.setText(_translate("MainWindow", "Percentage of other:", None))
        item = self.listWidget.item(7)
        item.setText(_translate("MainWindow", "total size:", None))
        item = self.listWidget.item(8)
        item.setText(_translate("MainWindow", "time diff:", None))
        item = self.listWidget.item(9)
        item.setText(_translate("MainWindow", "Bit per second:", None))
        self.listWidget.setSortingEnabled(__sortingEnabled)

    def capture_wifi(self):
        os.system("{tshark_loc} -i Wi-Fi -a duration:15 -w sniff_output.pcapng".format(tshark_loc=r'"C:\Program Files\Wireshark\tshark"'))  #Starting wireshark in silent mode
        self.progressBar.setEnabled(True)
        self.completed = 0
        while self.completed < 100:
            time.sleep(1)
            self.completed += (100/5)
            self.progressBar.setValue(self.completed)
        inter_ip=socket.gethostname()
        inter_ip=socket.gethostbyname(inter_ip)
        f = open("sniff_output.pcapng", mode= "rb")                #pass the file argument to the pcapng.Reader function  (file)
        pcap = dpkt.pcapng.Reader(f)    #parsing the pcapng file using dpkt package  (iterable)
        size_sum = 0                    #size_sum is the total size of the package (it is initialized to zero as there is no package in the beginning) (integer)
        first = True                    #flag to see if it's the first package (integer)
        ts_first = 0                    #first timestamp (integer)
        ts_last = 0                     #last timestamp (integer)
        arp=0
        https=0
        http=0
        dns=0
        udp=0
        tcp=0
        els=0
        tot=0
        for ts, buf in pcap:                        #loop for all the requests in the pcapng File (a tuple of buffer and timestamp respectively)
            eth = dpkt.ethernet.Ethernet(buf)                    #converting it to eth object
            ip = eth.data                                   # to read the source IP in src (IP object)
            protocol=ip.data                            # to read which protocol the packet is in
            tot+=1
            if(type(ip)==type(dpkt.arp.ARP())):                    #if packet is in ARP protocol
                arp+=1
            elif(type(protocol)==type(dpkt.udp.UDP())):                 #if packet is in UDP protocol
                if(protocol.dport==53 or protocol.sport==53):           #if packet is a dns service
                    dns+=1
                elif(protocol.dport==443 or protocol.sport==443):       #if packet is a https service
                    https+=1
                else:
                    udp+=1
            elif(type(protocol)==type(dpkt.tcp.TCP())):                 #if packet is in TCP protocol
                if(protocol.dport==443 or protocol.sport==443):             #if packet is a https service
                    https+=1
                elif(protocol.dport==80 or protocol.sport==80):         #if packet is a http service
                    http+=1
                else:
                    tcp+=1
            else:
                els+=1

            if type(ip == dpkt.ip.IP and socket.inet_ntoa(ip.src) == inter_ip):     #we are checking if the source of the package is the connection we want
                if first:                           #checking it it's the first package
                    first =False                            # (boolean)
                    ts_first = ts                   #assigning the first timestamp
                try:
                    size_sum += ip.len           #analyzing the total size of the packages by adding the size of individual package
                except:
                    pass
                ts_last=ts                    #assigning the last timestamp
        ts_diff = ts_last - ts_first                #taking the timestamp difference to know the total time taken  (integer)
        speed = size_sum/ts_diff                    #dividing the timestamp difference with the totla size of the packages to get the speed (integer)
        arp=float(arp/tot)*100
        https=float(https/tot)*100
        http=float(http/tot)*100
        dns=float(dns/tot)*100
        tcp=float(tcp/tot)*100
        udp=float(udp/tot)*100
        els=float(els/tot)*100
        print ("Percentage of ARP:%.3f" %arp)
        print ("Percentage of HTTPS:%.3f" %https)
        print ("Percentage of HTTP:%.3f" %http)
        print ("Percentage of DNS:%.3f" %dns)
        print ("Percentage of other TCP:%.3f" %tcp)
        print ("Percentage of other UDP:%.3f" %udp)
        print ("Percentage of other:%.3f" %els)
        print ("total size %.3f" %size_sum)
        print("time diff %.3f" %ts_diff)
        print("Bit per second %.3f" %speed)
        f.close()                       #closing the file which opened pcapng file
        item = self.listWidget.item(0)
        item.setText(_translate("MainWindow", "Percentage of ARP:{arpw}".format(arpw=arp), None))
        item = self.listWidget.item(1)
        item.setText(_translate("MainWindow", "Percentage of HTTPS:{arpw}".format(arpw=https), None))
        item = self.listWidget.item(2)
        item.setText(_translate("MainWindow", "Percentage of HTTP:{arpw}".format(arpw=http), None))
        item = self.listWidget.item(3)
        item.setText(_translate("MainWindow", "Percentage of DNS:{arpw}".format(arpw=dns), None))
        item = self.listWidget.item(4)
        item.setText(_translate("MainWindow", "Percentage of other TCP:{arpw}".format(arpw=tcp), None))
        item = self.listWidget.item(5)
        item.setText(_translate("MainWindow", "Percentage of other UDP:{arpw}".format(arpw=udp), None))
        item = self.listWidget.item(6)
        item.setText(_translate("MainWindow", "Percentage of other:{arpw}".format(arpw=els), None))
        item = self.listWidget.item(7)
        item.setText(_translate("MainWindow", "total size:{arpw}".format(arpw=size_sum), None))
        item = self.listWidget.item(8)
        item.setText(_translate("MainWindow", "time diff:{arpw}".format(arpw=ts_diff), None))
        item = self.listWidget.item(9)
        item.setText(_translate("MainWindow", "Bit per second{arpw}".format(arpw=speed), None))
        self.listWidget.setSortingEnabled(__sortingEnabled)

    def send_req(self):
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)             #opening a socket connection
        except socket.error:
            print("Failed to send and recieve packets")

        print("Socket Created")
        host= "www.google.com"                              #sending packets to google.com
        port=80                                              #since it's an http request
        try:
            remote_ip = socket.gethostbyname(host)          #reading host ip
        except socket.galerror:
            print("Hostname could not be resolved")

        print("IP Address"+ remote_ip)
        s.connect((remote_ip, port))                    #connecting to the remote_ip through that port

        print("Socket Connected to " + host + " using IP" + remote_ip)
        message = "GET / HTTP/1.1\r\n\r\n"
        try:
            s.sendall(message.encode())                             #message is encoded and sent
        except socket.error:
            print("Did not send packet successfully")

        print("Message sent succesfully")
        reply = s.recv(4096)                            #message is recieved at port 4096
        print(reply.decode())                       #the recieved message is decoded and printed.
        fi = open("reply.html", mode= "wb")
        fi.write(reply.decode())
        fi.close()
        os.system("start chrome reply.html")
        s.close()


if __name__ == "__main__":
    import sys
    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
