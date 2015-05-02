#!/usr/bin/perl -w
use strict;
use File::Copy;

my $datetime = localtime;

#x times to ban
my $times = 5;

#Check Unauthorized attacks
my @auth_failure = blacklist('/var/log/freeswitch/freeswitch.log','auth failure',16,$times);

#Check RTP without registration attacks
my @rtp_attacks = blacklist('/var/log/freeswitch/freeswitch.log','Rejected by acl',5,$times);

#IP address of attackers
my @ip_blacklist = whitelist(@auth_failure,@rtp_attacks);

#Output for local check_mk
output_check_mk("Auth_Failure",@auth_failure);
output_check_mk("RTP_Attacks",@rtp_attacks);

#Block the attacker
blacklist2iptables(@ip_blacklist) if(@ip_blacklist > 0);

sub output_check_mk {
        my @blockedip = @_;
        my ($count,$ip_info,$name) = (0,'','');
        $name = $blockedip[0];
        $blockedip[0]=0;

        if(@blockedip > 0) {
            @blockedip = remove_duplicate_ip(@blockedip);

            foreach my $ip (@blockedip) {
                if($ip ne 0) {
                    $ip_info .= "|IP=$ip";
                    $count++;
                }
            }

            my $status = 0;
            my $statustxt="OK";
            if($count > 0) {
                $status = 2;
                $statustxt="CRITICAL";
            }

            print "$status SIP2BAN_$name attack=$count$ip_info Server is $statustxt, $datetime\n";

        } else {
            my $status = 0;
            my $statustxt="OK";
            print "$status SIP2BAN_$name attack=$count Server is $statustxt, $datetime\n";
        }

}

sub blacklist2iptables {

        my @blockedip = @_;

        @blockedip = remove_duplicate_ip(@blockedip);

        #apply new iptables rules
        my $newiptables;
        foreach my $ip (@blockedip) {
              if($ip ne 0) {
                  $newiptables .= "-A INPUT -s $ip -j DROP\n";
                  system("/sbin/iptables -I INPUT 2 -s $ip -j DROP");
              }
        }

        if(defined($newiptables)) {
            #read iptables configuration file
            open(my $fh, '<',"/etc/sysconfig/iptables") or die "Could not open file!";
            my @lines=<$fh>;
            close $fh;

            #backup iptables configuration file
            move("/etc/sysconfig/iptables","/etc/sysconfig/iptables.$datetime") or die "Can not backup iptables file!\n";

            #save new iptables rules
            open($fh, '>',"/etc/sysconfig/iptables") or die "Could not open file!";
            foreach my $line (@lines) {
                my $search = "-A INPUT -i lo -j ACCEPT";
                print $fh $line;
                print $fh $newiptables if($line =~ /$search/);
            }
            close $fh;
        }

}

sub remove_duplicate_ip {
        my @blockedip = @_;

        #read iptables configuration file
        open(my $fh, '<',"/etc/sysconfig/iptables") or die "Could not open file!";
        my @lines=<$fh>;
        close $fh;

        foreach my $line (@lines) {
           for(my $i=0; $i < @blockedip; $i++) {
                my $str = "-A INPUT -s $blockedip[$i] -j DROP";
                if($line =~ /$str/) {
                    $blockedip[$i]=0;
                }

           }
        }

        return  @blockedip;
}

sub uniq {
    my %seen;
    grep !$seen{$_}++, @_;
}

sub whitelist {

        my @blockedip = @_;

        @blockedip = uniq(@blockedip);

        #read and apply whitelist
        if(open(my $fh, '<', '/etc/sip2ban/whitelist.ini')) {
            my @whitelistlines=<$fh>;
            close $fh;
            foreach my $whitelist (@whitelistlines) {
                chomp $whitelist;
                for(my $i=0; $i < @blockedip; $i++) {
                     $blockedip[$i] = 0 if($whitelist =~ /$blockedip[$i]/);
                }
            }
        }

        return @blockedip;
}

sub blacklist {

        my ($logfile,$key,$index,$count) = ($_[0],$_[1],$_[2],$_[3]);
        my (@ip, $i) = (0, 0);
        #read opensips log file
        open(my $fh, '<', $logfile) or die "Could not open file '$logfile' $!";
        while (my $row = <$fh>) {
          chomp $row;
          if(index($row, $key) != -1) {
              my @data = split / /, $row;
              $ip[$i++] = $data[$index];
          }
        }
        close $fh;

        #if failed times >= count, it will be blacklist
        my %seen;
        foreach my $item (@ip) {
          $seen{$item}++;
        }

        $i=0;
        my @blockedip;
        foreach my $item (keys %seen) {
           if($seen{$item} >= $count) {
               $blockedip[$i++] = $item;
           }
        }

        return @blockedip;
}
