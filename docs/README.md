# How to use it:

# Server (after you setting up vps or your own server)
### This for debian-based:
### apt install gcc net-tools libssl-dev git
### git clone https://github.com/Default-Anon/cvpn
### go to src/headers/unix_net.h
### change it
### comment (AS_CLIENT)
## create secure aes key and initialisation vector
### dd if=/dev/urandom of=vpn.key count=1 bs=32
### base64 < vpn.key (copy output after this command)
### launch with root privileges (Tunnel only work with root)

# Client
### apt install gcc net-tools libssl-dev git
### git clone https://github.com/Default-Anon/cvpn
### go to src/headers/unix_net.h
### change it as you setup your server
### comment (AS_SERVER)
## paste the key what you copy on server as in example:
### echo hwvGruKbllczH1J64VJE927ChhrATzD35fIUL2M2QyY= | base64 --decode > vpn.key
### launch with root
    
 
