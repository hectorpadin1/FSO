# Prácticas Linux

## Securización del arranque

Para poner contraseña mediante usuario/password al grub:

```bash
grub-mkpasswd-pbkdf2
nano /etc/grub.d/41_custom :
    set superusers="root"
    password_pbkdf2 root <password>
```

Tras introducir los superusuarios en el sistema, requerirá un usuario y una contraseña para acceder a cualquier entrada, o mismo a la línea de comandos del grub.

Menús de entrada (se deben añadir en el archivo 40_custom):

```bash
menuentry "Only to be booted by a superuser or user1" --users <user> {
    set root=(hd0,2)
    ...
menuentry "Anyone can boot this" --unrestricted {
    set root=(hd0,2)
    ...
```

Para aplicar los cambios
    
```bash
grub-mkconfig (-o /boot/grub/grub.cfg) & update-grub
```

## Usuarios

* /etc/passwd: contiene información de los usuarios del sistema.
* /etc/shadow: los hashes de las contraseñas de los usuarios.
* /etc/group: contiene información de los grupos del sistema.
* /etc/gshadow: contiene información de los grupos del sistema.
* /etc/sudoers: contiene información de los usuarios que pueden usar sudo.

### Módulos PAM

Para una instalación concreta, un módulo puede considerarse: 
* sufficient: si este módulo permite el acceso, se concede el acceso, no se se comprueban más módulos.
* requisite: si este módulo deniega el acceso, se deniega el acceso, no se comprueban más módulos.
* required: este módulo debe conceder el acceso, y la evaluación continúa con los siguientes módulos.
* opcional: el resultado de este módulo sólo se utilizará si el resultado de ningún otro módulo es determinista.

```bash
service_name facility (auth, session, etc) control_flag (sufficient, requisite, required, optional) module options
```

/etc/pam.d: hay un archivo de texto plano en el directorio /etc/pam.d para cada servicio a configurar:
```bash
facility control_flag module options
```

Evitar login como root:

```bash
echo 'auth required pam_securetty.so' >> /etc/pam.d/login
echo 'auth required pam_securetty.so' >> /etc/pam.d/lightdm
echo 'tty3' >> /etc/securetty # Excepciones
```

Fortificar:
* /etc/pam.d/login
* /etc/pam.d/common-auth
* /etc/pam.d/common-password
* /etc/pam.d/lightdm, /etc/pam.d/gdm, /etc/pam.d/sddm, etc.

### Autenticación

Permitir convertirse en root a determinados usuarios (grupo wheel):
```bash
groupadd wheel
usermod -a -G wheel <user>
echo 'auth required pam_wheel.so' >> /etc/pam.d/su
echo 'auth sufficient pam_wheel.so group=<group> trust' >> /etc/pam.d/su # permitir a cierto grupo hacerse root sin contraseña
```

Añadir requisitos a las contraseñas (10 char, upper and lowercase, five digits, one non alphanumeric character, no be one of the last three passwords used):

```bash
cat /etc/pam.d/common-password

password requisite pam_cracklib.so minlen=10 dcredit=-5 ucredit=-1 lcredit=-1 ocredit=-1
password requisite pam_pwhistory.so remember=3
```

Shells restringidos (no cd, solo permite / dentro del PATH, no modifica variables de entorno, no redirige stout-in):
```bash
cat /etc/passwd | grep /bin/rbash
user:x:1000:1000::/home/user:/bin/rbash
mkdir /home/user/bin
ln -s /bin/ls /home/user/bin/ls
chown root:root .bashrc
chmod +t /home/user/ # Impide que se borren ficheros en el directorio
```

Permitir a un usuario/grupo ejecutar comandos de root:
```bash
visudo
user ALL=(root) NOPASSWD: /usr/bin/whoami # sin necesidad de contraseña
user ALL=(ALL:ALL) /usr/bin/whoami # con contraseña
%adm ALL=(root) NOPASSWD: ALL # todos los comandos
%adm ALL=(ALL:ALL) /usr/bin/whoami # con contraseña
```

Permitir o restringir a ciertos usuarios convertirse en root:
```bash
echo 'auth sufficient pam_wheel.so group=no_passwd root_only trust' >> /etc/pam.d/su
echo 'auth requisite pam_wheel.so deny group=no_root root_only' >> /etc/pam.d/su
```

Autenticación de doble factor con Google:
```bash
apt-get install google-authenticator
google-authenticator # configurar
echo 'ChallengeResponseAuthentication yes' >> /etc/ssh/sshd_config
echo 'auth required pam_google_authenticator.so' >> /etc/pam.d/sshd
echo 'auth required pam_google_authenticator.so nullok' >> /etc/pam.d/lightdm
```

Login ssh con claves:
```bash
cd .ssh
ssh-keygen -t rsa -b 4096
cat id_rsa.pub 
    id-rsa
ssh user@host
echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config
echo 'id-rsa' >> /etc/ssh/authorized_keys
```

Permitir cualquier login gráfico:
```bash
echo 'auth sufficient pam_permit.so' >> /etc/pam.d/lightdm
```

## Sistemas de ficheros

### Cuotas de usuarios

* **quotacheck**: crea, comprueba y/o repara los archivos de cuota en un sistema de archivos.
* **quotaon-off**: activa (o desactiva) las cuotas en un sistema de archivos.
* **edquota**: permite modificar las cuotas de un usuario (o grupo).
* **repquota**: quota informa del estado de las cuotas en un sistema de archivos sistema.
* **edquota -u user**: abre el editor definido en $EDITOR para que para modificar los límites blandos y duros para el nombre de usuario.
* **edquota -g grpname**: abre el editor definido en $EDITOR para que modifiquemos los límites blandos y duros del grupo grpname.
* **edquota -p copy paste**: establece cuotas para nombre de usuario lo mismo que el prototipo de usuario.
* **edquota -t**: establece el periodo de gracia

Para que cuando se levante el sistema se añadan las opciones de las, se debe modificar el archivo /etc/fstab, añadiendo lo siguiente:
    
```bash
UUID=...    /home   ext4    defaults,usrquota   0   0
```

Añadir restricciones de tamaño de los directorios /home (20Mb 23 max) y límite de inodos (40, 50 max):
```bash
edquota -u user
    Filesystem  blocks  soft    hard    inodes  soft    hard
    /fs            256 20000   23000        36    40      50
edquota -t
    Filesystem  Blocks grace time   Inodes grace time
    /fs              2 days               2 days
# copiar la config a todos los usuarios
for name in `cat /etc/passwd | grep /bin/sh | cut -f1 -d:`; do edquota -p user $name; done
quota -v    # Ver cuotas actuales del usuario
```

### ACLs

Creación de ACLs sobre un fichero:

```bash
touch file
ls -l file
    -rw------- 1 root root 0 Feb  2 12:00 file
getfacl file
    # file: file
    # owner: root
    # group: root
    user::rw-
    group::---
    other::---
setfacl -m "u:user:rw" file # Un usuario
getfacl file
    # file: file
    # owner: root
    # group: root
    user::rw-
    user:user:rw-
    group::---
    mask::rw-
    other::---
setfacl -m "g:group:rw" /etc/passwd # Grupo de usuarios
getfacl /etc/passwd
    # file: file
    # owner: root
    # group: root
    user::rw-
    group::r--
    group:group:rw-
    mask::rw-
    other::---
setfacl -b file # Borrar ACLs
```

### Sistema de ficheros cifrado

Creacion de particiones:
```bash
fdisk /dev/sda
    > n (new partition)
    > 2 (number)
    > int (default) (first sector)
    > int (fst sector - last sector)
    > w (write and exit)
```

Creación de sistema de ficheros cifrado:
```bash
cryptsetup open /dev/sdb1 crypt1 --type plain   # cifrado plano
mkfs.ext4 /dev/mapper/crypt1
mount /dev/mapper/crypt1 /mnt
umount /mnt
cryptsetup close crypt1

cryptsetup -y -v luksFormat --type luks /dev/sdb2   # cifrado LUKS
cryptsetup open /dev/sdb2 crypt2
mkfs.ext4 /dev/mapper/crypt2
mount /dev/mapper/crypt2 /mnt
cryptsetup luksAddKey /dev/sdb2         # añadir clave
```

Creación de un volumen cifrado:

```bash
# Creación de FS
cryptsetup open /dev/sdb1 crypt1 --type plain
cryptsetup -y -v luksFormat --type luks /dev/sdb2
cryptsetup open /dev/sdb2 crypt2
# Volúmenes físicos
pvcreate /dev/mapper/crypt1 /dev/mapper/crypt2
pvdisplay | grep crypt
# Grupo de volúmenes
vgcreate GROUP /dev/mapper/crypt1 
vgextend GROUP /dev/mapper/crypt2
# Volúmen lógico
lvcreate -L 100MB -n lv1 GROUP
# Creación de FS
mkfs.ext4 /dev/mapper/GROUP/lv1
mount /dev/mapper/GROUP/lv1 /mnt
```

Restaurar un volumen cifrado:
```bash
cryptsetup open /dev/sdb1 crypt1 --type plain
cryptsetup open /dev/sdb2 crypt2
mount /dev/GROUP/lv1 /mnt
```

Encriptado de directorios:
```bash
encfs /home/user/crypted /home/user/clear
ls clear
File1 File2 File3
ls crypted/
dPs3OXDuMOBNoY-E3xxer1kQ jHmBig77BxJ5p6WRFoqrRlTe T4siEtLQ,9jkWBRDsTzjE2w0
fusermount -u /home/user/clear # unmount
encfs /home/user/crypted /home/user/clear # mount
```

## Aplicaciones

### Gestión de recursos

Uso de cpulimit para restringir el uso de la cpu de un programa:
```bash
cpulimit -l <limit> -p <PID>
```

Uso de cgroups para limitar el uso de recursos de un proceso:
```bash
mkdir /sys/fs/cgroup/group
echo PID > /sys/fs/cgroup/group/cgroup.procs
echo 1000000 > /sys/fs/cgroup/group/memory.high
echo 1 > /sys/fs/cgroup/group/cgroup.freeze
```

### Contenedores

Creación de contenedores:
```bash
lxc-create -t debian -n name
lxc-start -n name
lxc-attach -n name
root@name: apt-get install pkg
```

### AppArmor

Creación de un perfil (lectura en $HOME/C y escritura en ficheros .c a excepción de secret.c):
```bash
aa-easyprof /usr/bin/program > /etc/apparmor.d/usr.bin.program
cat /etc/apparmor.d/usr.bin.program
    "usr/bin/program" {
     @{HOME}/dir/ r,
     @{HOME}/dir/*.c rw,
     deny @{HOME}/dir/secret.c rw,
    }
```

### Network

El ficheor /etc/network/interfaces contiene la configuración de las interfaces de red.

El servicio inetd se encarga de la ejecución de los servicios de red. Para habilitar un servicio:
```bash
echo 'ftp stream tcp nowait root /usr/sbin/tcpd ftpd' >> /etc/inetd.conf
```

### TCP Wrappers

Consta de dos archivos de configuración, /etc/hosts.allow y /etc/hosts.deny. El primero contiene las reglas de acceso y el segundo las reglas de denegación.

Ejemplo de host.deny:
```bash
ALL: ALL # Denegar todo
```

Ejemplo de host.allow:
```bash
ftpd: 192.168.10.103
ftpd: 10.0.1.*
sshd: *
```

Se puede bypassear los wrappers para determinados servicios mediante inetd, por ejemplo añadiendo el servicio ftp al fichero /etc/inetd.conf sobre ftpd y no sobre tcpd:
```bash
ftp stream tcp nowait root /usr/sbin/tcpd ftpd
```

### nftables

Ejemplo de fichero de configuración:
```bash
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0;
        ct state established,related accept
        iif lo accept
        tcp dport { 22, 80, 443 } log
        tcp dport { 22, 80, 443 } accept
        ip saddr 10.0.1.0/24 dport { 22, 80, 443 } drop # bloquear acceso desde una red
        ip saddr 10.0.10.0/24 dport { 22, 80, 443 } reject  # reject with icmp port unreachable
        reject with icmpx type port-unreachable
    }
    chain output {
        type filter hook output priority 0;
        ct state established,related accept
        oif lo accept
        tcp sport { 22, 80, 443 } accept
        reject with icmpx type port-unreachable
    }
    chain forward {
        type filter hook forward priority 0;
        ct state established,related accept
        reject with icmpx type port-unreachable
    }
    chain prerouting {
        type nat hook prerouting priority -100;
    }
    chain postrouting {
        type nat hook postrouting priority -100;
    }   
}
```

Para redirigir un puerto de la máquina al contenedor:
```bash
root@container: echo 'auto eth0\n\tiface eth0 inet static\n\taddress 10.0.3.14\n\tgateway 10.0.3.1' >> /etc/network/interfaces
root@container: exit
echo '1' > /proc/sys/net/ipv4/ip_forward
nano /etc/nftables.conf
    ...
    table ip nat {
        chain prerouting {
            type nat hook prerouting priority -100;
            tcp dport 22 log prefix "nat-pre " dnat 10.0.3.14:22;
        }
    }
```

```bash
nft add table container
nft add chain container web '{ type nat hook prerouting priotity dsnat; }'
nft add rule container web tcp dport 80 dnat to <container-ip>:80
```

Aplicar una cadena a una regla de entrada:
```bash
nft add rule filter INPUT ip saddr '{ 10.0.1.101, 10.0.2.101 }' jump CUSTOM_CHAIN
```

## Monitorización

Para enviar logs de una máquina a otra se debe añadir en el fichero de /etc/rsyslog.conf:
```bash
auth,authpriv.* @<ip>
auth,authpriv.* <tty>
auth,authpriv.* /var/log/auth.log
```

Y en la máquina receptora:
```bash
module(load="imtcp")
module(type="imtcp"port="514")
module(load="imudp")
module(type="imudp"port="514")
