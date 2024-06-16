#!/bin/sh

. /lib/functions.sh
. /lib/functions/network.sh
. ../netifd-proto.sh
init_proto "$@"

proto_xmm_init_config() {
    no_device=1
    available=1
    proto_config_add_string "device:device"
    proto_config_add_string "apn"
    proto_config_add_string "pdp"
    proto_config_add_int  "delay"
    proto_config_add_string "username"
    proto_config_add_string "password"
    proto_config_add_string "auth"
	proto_config_add_int "profile"
    proto_config_add_defaults
}

proto_xmm_setup() {
    local interface="$1"
    local devname devpath hwaddr DNS1 DNS2 DNS3 DNS4 ip ip6 OX
    local name ifname proto extendprefix auth username password
    local device ifname auth username password apn pdp pincode delay profile $PROTO_DEFAULT_OPTIONS
    json_get_vars device ifname auth username password apn pdp pincode delay profile $PROTO_DEFAULT_OPTIONS
	
	uci -q delete network.$interface.constate
    uci -q commit
	
	[ "$profile" = "" ] && profile="1"
    [ "$metric" = "" ] && metric="0"
    [ -z $ifname ] && {
		devname=$(basename $device)
		case "$devname" in
			*ttyACM*)
				echo "Setup xmm interface $interface with port ${device}"
				devpath="$(readlink -f /sys/class/tty/$devname/device)"
				[ "${devpath}x" != "x" ] && {
					echo "Found path $devpath"
					hwaddr="$(ls -1 $devpath/../*/net/*/*address*)"
					for h in $hwaddr; do
						if [ "$(cat ${h})" = "00:00:11:12:13:14" ]; then
							ifname=$(echo ${h} | awk -F [\/] '{print $(NF-1)}')
						fi
					done
				} || {
					[ -n $delay ] && sleep $delay || sleep 5
					echo "Device path not found!"
					proto_notify_error "$interface" NO_DEVICE_FOUND
					return 1
				}
			;;
		esac
	}

    [ -n "$ifname" ] && {
        echo "Found interface $ifname"
    } || {
        echo "The interface could not be found."
        proto_notify_error "$interface" NO_IFACE
        proto_set_available "$interface" 0
        return 1
    }

	CID=$profile
    pdp=$(echo $pdp | awk '{print toupper($0)}')
    [ "$pdp" = "IP" -o "$pdp" = "IPV6" -o "$pdp" = "IPV4V6" ] || pdp="IP"
    echo "Setting up $ifname"
    [ -n "$delay" ] && sleep "$delay" || sleep 5
    [ -n "$username" ] && [ -n "$password" ] && {
        echo "Using auth type is: $auth"
        case $auth in
        pap) AUTH=1 ;;
        chap) AUTH=2 ;;
        *) AUTH=0 ;;
        esac
        AUTH=$AUTH 
        USER=$username 
        PASS=$password 

        export ATCMD="AT+XGAUTH=$CID,$AUTH,\"$USER\",\"$PASS\""
        gcom -d $device -s /etc/gcom/run-at.gcom >/dev/null 2>&1
    }
	
	OX=$(runatcmd "$device" "AT+CGACT=0,$CID")
	OX=$(runatcmd "$device" "AT+CGDCONT?;+CFUN?")
	
	if `echo $OX | grep "+CGDCONT: $CID,\"$pdp\",\"$apn\"," 1>/dev/null 2>&1`
	then
		if [ -z "$(echo $OX | grep -o "+CFUN: 1")" ]; then
			OX=$(runatcmd "$device" "AT+CFUN=1")
		fi
	else
		local ATCMDD="AT+CGDCONT=$CID,\"$pdp\",\"$apn\""
		OX=$(runatcmd "$device" "$ATCMDD")
		
		OX=$(runatcmd "$device" "AT+CFUN=4")
		OX=$(runatcmd "$device" "AT+CFUN=1")
		sleep 5
	fi
	
	OX=$(runatcmd "$device" "AT+CGPIAF=1,0,0,0;+XDNS=$CID,1;+XDNS=$CID,2")
	OX=$(runatcmd "$device" "AT+CGACT=1,$CID")
	
	proto_init_update "$ifname" 1
    proto_add_data
    proto_close_data
	
	local ERROR="ERROR"
	OX=$(runatcmd "$device" "AT+CGCONTRDP=$CID")
	if `echo "$OX" | grep -q "$ERROR"`; then
		echo "Failed to get IP information for context"
		proto_notify_error "$interface" CONFIGURE_FAILED
        return 1
	else
	    OX=$(echo "${OX//[\" ]/}")
	    ip=$(echo $OX | cut -d, -f4 | grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}")
		ip=$(echo $ip | cut -d' ' -f1)
	    DNS1=$(echo $OX | cut -d, -f6)
		DNS2=$(echo $OX | cut -d, -f7)
		local OX6=$(echo $OX | grep -o "+CGCONTRDP:$CID,[0-9]\+,[^,]\+,[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}.\+")
		ip6=$(echo $OX6 | grep -o "[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}")
		ip6=$(echo $ip6 | cut -d' ' -f1)
		DNS3=$(echo "$OX6" | cut -d, -f6)
		DNS4=$(echo "$OX6" | cut -d, -f7)
		
        echo "PDP type is: $pdp"
		echo "IP address(es): $ip $ip6"
		echo "DNS servers 1&2: $DNS1 $DNS2"
		echo "DNS servers 3&4: $DNS3 $DNS4"

		if [[ $(echo "$ip6" | grep -o "^[23]") ]]; then
			# Global unicast IP acquired
			v6cap=1
		elif [[ $(echo "$ip6" | grep -o "^[0-9a-fA-F]\{1,4\}:") ]]; then
			# non-routable address
			v6cap=2
		else
			v6cap=0
		fi

		if [ -n "$ip6" -a -z "$ip" ]; then
			echo "Running IPv6-only mode"
			nat46=1
		fi

		OX=$(runatcmd "$device" "AT+XDATACHANNEL=1,1,\"/USBCDC/2\",\"/USBHS/NCM/0\",2,$CID")
		
		proto_set_keep 1
        ip link set dev $ifname arp off
		proto_add_ipv4_address $ip 32
		proto_add_ipv4_route "0.0.0.0" 0 "0.0.0.0" $ip
		
		local defdns=$(uci -q get network.$interface.dns)
		if [ -n "$defdns" ]; then
			echo "Using custom dns"

			set -- $defdns
			for value in "$@"
			do
			proto_add_dns_server "$value"
			done
		else
			echo "Using default dns"
			proto_add_dns_server "$DNS1"
			proto_add_dns_server "$DNS2"
		fi
		
		proto_add_data
        proto_close_data
        proto_send_update "$interface"
		
		if [ "$v6cap" -gt 0 ]; then
		   ip -6 address add ${ip6}/64 dev $ifname
		   ip -6 route add default via "$ip6" dev "$ifname"
           json_init
           json_add_string name "${interface}_6"
           json_add_string ifname "@$interface"
           json_add_string proto "dhcpv6"
           json_add_string extendprefix 1
           proto_add_dynamic_defaults
           json_close_object
           ubus call network add_dynamic "$(json_dump)"
		fi
		
		export ATCMD="AT+CGDATA=\"M-RAW_IP\",$CID"
		OX=$(gcom -d $device -s /etc/gcom/run-at.gcom)
		local RESP=$(echo $OX | sed "s/AT+CGDATA=\"M-RAW_IP\",$CID //")
		echo "Final Modem result code is \"$RESP\""
	fi

    echo "Starting monitor connection"

    uci -q set network.$interface.constate="connect"
    uci -q commit

    monitor_link $interface $ifname
}

monitor_link(){
    local interface=$1
    local ifname=$2
	local curr_dev_name if_state if_dev_state con_state
    ip monitor link | while read -r line; do
        curr_dev_name=$(echo "$line" | awk -F': ' '{print $2}')

        if_state=$(ubus call network.interface.$interface status | jsonfilter -e '@.up')
        if_dev_state=$(ip link show dev $ifname | grep -oE 'state [A-Z]+ ' | grep -oE '[A-Z]+')

        if [ "$curr_dev_name" != "$ifname" ]; then
            continue
        fi

        if [ "$if_state" = "true" ] && [ "$if_dev_state" = "DOWN" ]; then
            con_state=$(uci -q get network.$interface.constate)
            # handling ip lost
            if [ "$con_state" = "connect" ]; then
                uci -q set network.$interface.constate="reconnect"
                uci -q commit

                echo "$interface is up but $ifname ip link is down, restarting modem"

                ifdown $interface
                ifup $interface

                echo "stopping connection monitor"
                break
            fi
        fi
    done
}

runatcmd(){
	export ATCMD=$2
	gcom -d $1 -s /etc/gcom/run-at.gcom
}


killMonitor() {
    local pids=$(pgrep -f "ip monitor link")

    if [ -n "$pids" ]; then
        for pid in $pids; do
            kill "$pid"
        done

        echo "All 'ip monitor link' processes killed."
    else
        echo "No processes found with 'ip monitor link' pattern."
    fi
}

proto_xmm_teardown() {
	killMonitor
	
    local interface="$1"
    local device
    device=$(uci -q get network.$interface.device)
	
    export ATCMD="AT+CGACT=0"
    gcom -d $device -s /etc/gcom/run-at.gcom >/dev/null 2>&1
    export ATCMD="AT+XDATACHANNEL=0"
    gcom -d $device -s /etc/gcom/run-at.gcom >/dev/null 2>&1
	
    echo "Modem $device disconnected"
    proto_kill_command "$interface"
}

add_protocol xmm
