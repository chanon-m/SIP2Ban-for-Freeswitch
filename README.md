# SIP2Ban-for-Freeswitch
Avoided SIP and RTP attackers in FreeSwitch with Check_MK

#Licensing Information: READ LICENSE

#Project source can be downloaded from
###https://github.com/chanon-m/sip2ban-for-freeswitch.git

#Author & Contributor

Chanon Mingsuwan

Reported bugs or requested new feature can be sent to chanonm@live.com

#Check_MK agent installation and configuration

```

# yum install xinetd check-mk-agent

```

```

# vim /etc/xinetd.d/check-mk-agent

# configure the IP address(es) of your Nagios server here:
only_from = 192.168.10.10

```

```

# service xinetd start
# chkconfig xinetd on

```
#How to run a file
* Download files to your remote server

```

# git clone https://github.com/chanon-m/sip2ban-for-freeswitch.git

```
