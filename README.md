# SIP2Ban-for-Freeswitch
Avoided SIP and RTP attackers in FreeSwitch with Check_MK

#Licensing Information: READ LICENSE

#Project source can be downloaded from
###https://github.com/chanon-m/sip2ban-for-freeswitch.git

#Author & Contributor

Chanon Mingsuwan

Reported bugs or requested new feature can be sent to chanonm@live.com

#Snapshot

![Alt text](http://www.icalleasy.com/images/sip2ban_freeswitch_1.png "Snapshot 1") 

![Alt text](http://www.icalleasy.com/images/sip2ban_freeswitch_2.png "Snapshot 2") 


##Check_MK agent installation and configuration

* Install Check_MK agent in remote node

```

# yum install xinetd check-mk-agent

```

* Allow Check_MK server to access check_mk_agent

```

# vim /etc/xinetd.d/check-mk-agent

# configure the IP address(es) of your Nagios server here:
only_from = 192.168.10.10

```

```

# vim /etc/sysconfig/iptables

-A INPUT -m state --state NEW -m tcp -p tcp --dport 6556 -j ACCEPT

```

* Start the service

```

# service xinetd start
# chkconfig xinetd on

```

#How to run a file

* Download files to your remote server

```

# git clone https://github.com/chanon-m/sip2ban-for-freeswitch.git

```

* Copy sip2ban_mk.pl to /usr/share/check-mk-agent/local/300

```

# cp ./sip2ban-for-freeswitch/sip2ban_mk.pl /usr/share/check-mk-agent/local/300

```

* Make a file executable

```

# chmod 755 /usr/share/check-mk-agent/local/300/sip2ban_mk.pl

```
