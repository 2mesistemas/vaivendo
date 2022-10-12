#!/usr/bin/env bash

# Antonio Marcos Sampaio Valadão


VERSION="v1.93"

CONFFILE="/opt/etc/vpn.conf"

[[ -f "${CONFFILE}" ]] && . "${CONFFILE}"

 
[[ -z "$VPN" ]] && VPN="vpn2.tjrj.jus.br"
[[ -z "$VPNIP" ]] && VPNIP="45.166.79.254"
[[ -z "$CHROOT" ]] && CHROOT="/opt/chroot"

[[ -z "$SPLIT" ]] && SPLIT=""

[[ -z "$SSLVPN" ]] && SSLVPN="sslvpn"

[[ -z "${TZ}" ]] && TZ='America/Sao_Paulo'

VARIANT="minbase"
RELEASE="bullseye"
DEBIANREPO="http://deb.debian.org/debian/"

GITHUB_REPO="2mesistemas/vm"

VER_BOOTSTRAP="1.0.127"
DEB_BOOTSTRAP="${DEBIANREPO}pool/main/d/debootstrap/debootstrap_${VER_BOOTSTRAP}_all.deb"
DEB_FILE=$(basename ${DEB_BOOTSTRAP})
SRC_BOOTSTRAP="${DEBIANREPO}pool/main/d/debootstrap/debootstrap_${VER_BOOTSTRAP}.tar.gz"

URL_VPN_TEST="https://www.debian.org"

[[ -z "${DISPLAY}" ]] && export DISPLAY=":0.0"

export LC_ALL=C LANG=C

SCRIPT=$(realpath "${BASH_SOURCE[0]}")

SCRIPTNAME=$(basename "${SCRIPT}")

args=("$@")

TUNSNX="tunsnx"

XDGAUTO="/etc/xdg/autostart/cshell.desktop"

INSTALLSCRIPT="/usr/local/bin/${SCRIPTNAME}"
PKGSCRIPT="/usr/bin/vpn.sh"

CSHELL_USER="cshell"
CSHELL_UID="9000"
CSHELL_GROUP="${CSHELL_USER}"
CSHELL_GID="9000"
CSHELL_HOME="/home/${CSHELL_USER}"

true=0
false=1

PATH="/sbin:/usr/sbin:/bin:/usr/sbin:${PATH}"

JAVA8=false

DNF="dnf"

do_help()
{

   cat <<-EOF1

Cliente VPN para Debian/Ubuntu

Versão do Checkpoint ${VERSION}

	
	-i|--install install mode - creates chroot
	-c|--chroot  changes default chroot ${CHROOT} directory
	-h|--help    shows this help
	-v|--version script version
	-f|--file    alternate conf file. Default /opt/etc/vpn.conf
	--vpn        selects the VPN DNS full name at install time
	--oldjava    JDK 8 for connecting to old Checkpoint VPN servers (circa 2019) *experimental*
	--proxy      proxy to use in apt inside chroot 'http://user:pass@IP'
	--portalurl  custom VPN portal URL prefix (usually sslvpn) ;
                     use it as --portalurl=STRING together with --install
	-o|--output  redirects ALL output for FILE
	-s|--silent  special case of output, no arguments
	
	start        starts    CShell daemon
	stop         stops     CShell daemon
	restart      restarts  CShell daemon
	status       checks if CShell daemon is running
	disconnect   disconnects VPN/SNX session from the command line
	split        split tunnel VPN mode - use only after session is up
	uninstall    deletes chroot and host file(s)
	rmchroot     deletes chroot
	selfupdate   self updates this script if new version available
	fixdns       tries to fix resolv.conf
	

	EOF1

   exit 0
}


die() 
{
   echo "${FUNCNAME[2]}->${FUNCNAME[1]}: $*" >&2 

   exit 2 
}  


vpnlookup()
{
   VPNIP=$(getent ahostsv4 "${VPN}" | awk 'NR==1 { print $1 } ' )
   [[ -z "${VPNIP}" ]] && die "could not resolve ${VPN} DNS name"
}


ingroup()
{ 
   [[ " `id -Gn ${2-}` " == *" $1 "*  ]];
}


needs_arg() 
{ 
   [[ -z "${OPTARG}" ]] && die "No arg for --$OPT option"
}


doOutput()
{
   LOG_FILE="$1"

   exec 1<&-
   exec 2<&-

   exec 1<> "${LOG_FILE}"

   exec 2>&1
}


doGetOpts()
{
   install=false

   while getopts dic:-:o:shvf: OPT
   do

      if [[ "${OPT}" = "-" ]]
      then   
         OPT=${OPTARG%%=*}
         OPTARG=${OPTARG#"$OPT"}
         OPTARG=${OPTARG#=}
      fi

      case "${OPT}" in

         i | install )     install=true ;;
         c | chroot )      needs_arg
                           CHROOT="${OPTARG}" ;;
         vpn )             needs_arg
                           VPN="${OPTARG}" 
                           vpnlookup ;;
         proxy )           needs_arg
                           CHROOTPROXY="${OPTARG}" ;;
         portalurl )       needs_arg
                           SSLVPN="${OPTARG}" ;;
         oldjava )         JAVA8=true ;;
         v | version )     echo "${VERSION}"
                           exit 0 ;;
         osver)            awk -F"=" '/^PRETTY_NAME/ { gsub("\"","");print $2 } ' /etc/os-release
                           exit 0 ;;
         o | output )      needs_arg
                           doOutput "${OPTARG}" ;;
         s | silent )      doOutput "/dev/null" ;;
         d | debug )       set -x ;;
         h | help )        do_help ;;
         f | file )        needs_arg
                           CONFFILE="${OPTARG}"
                           [[ -e $CONFFILE ]] || die "no configuration file $CONFFILE"
                           . "${CONFFILE}" ;; 
         ??* )             die "Illegal option --${OPT}" ;;
         ? )               exit 2;;

       esac

   done
}


getDistro()
{
   DEB=0
   RH=0
   ARCH=0
   SUSE=0
   GENTOO=0
   SLACKWARE=0
   VOID=0
   DEEPIN=0

   if [[ -f "/etc/debian_version" ]]
   then
      DEB=1

      ischroot && echo "Inside a chroot?" >&2

   else
      [[ -f "/etc/os-release" ]] && [[ $(awk -F= ' /^ID=/ { print $2 } ' /etc/os-release) == "debian" ]] && DEB=1
   fi


   [[ -f "/etc/os-version" ]] && [[ $(awk -F= '/SystemName=/ { print $2 } ' /etc/os-version) == Deepin ]] && DEEPIN=1 && DEBIAN=1

   [[ -f "/etc/redhat-release" ]]    && RH=1
   [[ -f "/etc/os-release" ]] && [[ $(awk -F= ' /^ID=/ { print $2 } ' /etc/os-release) == "openEuler" ]] && RH=1
   [[ -f "/etc/os-release" ]] && [[ $(awk -F= ' /^ID=/ { print $2 } ' /etc/os-release) == "Euler" ]] && RH=1

   [[ -f "/etc/arch-release" ]]      && ARCH=1
   [[ -f "/etc/os-release" ]] && [[ $(awk -F= ' /^ID_LIKE=/ { print $2 } ' /etc/os-release) == "arch" ]] && ARCH=1

   [[ -f "/etc/SUSE-brand" ]]        && SUSE=1

   [[ -f "/etc/gentoo-release" ]]    && GENTOO=1
   [[ -f "/etc/redcore-release" ]]   && GENTOO=1

   [[ -f "/etc/slackware-version" ]] && SLACKWARE=1

   [[ -f "/etc/os-release" ]] && [[ $(awk -F= ' /^DISTRIB/ { gsub("\"", ""); print $2 } ' /etc/os-release) == "void" ]] && VOID=1

   [[ "${DEB}" -eq 0 ]] && [[ "${RH}" -eq 0 ]] && [[ "${ARCH}" -eq 0 ]] && [[ "${SUSE}" -eq 0 ]] && [[ "${GENTOO}" -eq 0 ]] && [[ "${SLACKWARE}" -eq 0 ]] && [[ "${VOID}" -eq 0 ]] && die "Only Debian, RedHat, ArchLinux, SUSE, Gentoo, Slackware, and Void family distributions supported"
}


PreCheck()
{
   if [[ "$(uname -m)" != 'x86_64' ]] && [[ "$(uname -m)" != 'i386' ]]
   then
      die "This script is for Debian/RedHat/Arch/SUSE/Gentoo/Slackware/Void/Deepin Linux Intel based flavours only"
   fi

   getDistro

   if [[ -z "${VPN}" ]] || [[ -z "${VPNIP}" ]] 
   then
      [[ "$1" != "uninstall" ]] && [[ "$1" != "selfupdate" ]] && [[ "$1" != "rmchroot" ]] && die "Run vpn.sh -i --vpn=FQDN or fill in VPN and VPNIP with the DNS FQDN and the IP address of your Checkpoint VPN server"
   fi

   if [[ "${EUID}" -ne 0 ]]
   then
      which sudo &>/dev/null || die "install sudo and configure sudoers/groups for this user"

      [[ $(sudo -l) !=  *"not allowed"* ]] || die "configure sudoers/groups for this user"

      exec sudo "$0" "${args[@]}"
   else
      which sudo &>/dev/null || echo "you might want to install sudo" >&2
   fi
}


doChroot()
{
   setarch i386 chroot "${CHROOT}" "$@"
}


isCShellRunning()
{
   pgrep -f CShell &> /dev/null
   return $?
}


mountChrootFS()
{
   if ! isCShellRunning
   then

      mount | grep "${CHROOT}" &> /dev/null
      if [[ $? -eq 1 ]]
      then
         [[ ! -f "${CHROOT}/etc/fstab" ]] && die "no ${CHROOT}/etc/fstab"

         mount --fstab "${CHROOT}/etc/fstab" -a

        if [[ -d /run/nscd ]]
        then
           mkdir -p "${CHROOT}/nscd"
           mount --bind "${CHROOT}/nscd" "${CHROOT}/run/nscd"
        fi

         if ! mount | grep "${CHROOT}" &> /dev/null
         then
            die "mount failed"
         fi
      fi

   fi
}


umountChrootFS()
{
   if mount | grep "${CHROOT}" &> /dev/null
   then

      [[ -f "${CHROOT}/etc/fstab" ]] && doChroot /usr/bin/umount -a 2> /dev/null
         
      for i in $(mount | grep "${CHROOT}" | awk ' { print  $3 } ' )
      do
         umount "$i" 2> /dev/null
         umount -l "$i" 2> /dev/null
      done

      for i in $(mount | grep "${CHROOT}" | awk ' { print  $3 } ' )
      do
         umount -l "$i" 2> /dev/null
      done
   fi
}


FirefoxJSONpolicy()
{
   cat <<-EOF14 > "$1/policies.json"
	{
	   "policies": {
	               "ImportEnterpriseRoots": true,
	               "Certificates": {
	               "Install": [
	                          "${CHROOT}/usr/bin/cshell/cert/CShell_Certificate.crt"
	                          ]
	                               }
	               }
	}
	EOF14
}


FirefoxPolicy()
{
   local DIR
   local PolInstalled

   PolInstalled=0

   if [[ "$1" == "install" ]]
   then
      [[ -d "/usr/lib64/firefox" ]] && mkdir "/usr/lib64/firefox/distribution" 2> /dev/null

      [[ ${VOID} -eq 1 ]] && mkdir "/usr/lib/firefox/distribution" 2> /dev/null
      [[ -d "/etc/firefox" ]] && mkdir /etc/firefox/policies 2> /dev/null

      [[ -d "/opt/firefox" ]] && mkdir /opt/firefox/distribution 2> /dev/null

      [[ -d "/opt/moz/firefox" ]] && mkdir /opt/moz/firefox/distribution 2> /dev/null

      [[ -d "/usr/lib64/mozilla" ]] && mkdir "/usr/lib64/mozilla/distribution" 2> /dev/null

   fi

   for DIR in "/etc/firefox/policies" $(find /usr/lib/*firefox*/distribution /usr/lib64/*firefox*/distribution /usr/share/*firefox*/distribution /opt/*firefox*/distribution /opt/moz/*firefox*/distribution /usr/lib64/*mozilla* -type d 2> /dev/null)
   do
      if  [[ "$1" == "install" ]] && [[ -d "${DIR}" ]]
      then
         if [[ ! -f "${DIR}/policies.json" ]] || grep CShell_Certificate "${DIR}/policies.json" &> /dev/null
         then

            if [[ "${DIR}" != "/etc/firefox/policies" ]]
            then
               PolInstalled=1
            fi

            FirefoxJSONpolicy "${DIR}"

         else
            echo "Another policy already found at ${DIR}." >&2
         fi
      fi

      if [[ "$1" == "uninstall" ]] && grep CShell_Certificate "${DIR}/policies.json" &> /dev/null
      then
         rm -f "${DIR}/policies.json"
      fi

   done

   if [[ "$PolInstalled" -eq 1 ]]
   then
      pgrep -f firefox &>/dev/null && pkill -9 -f firefox

      echo "Políticas de segurança criadas para o Firefox, acesse https://localhost:14186 para obter o certificado" >&2
      echo "Se estiver usando outro navegador, e se tiver alguma dificuldade, use o Firefox ao menos no primeiro acesso." >&2
   fi
}


Split()
{
   if [[ -z "${SPLIT+x}" ]]
   then
      echo "If this does not work, please fill in SPLIT with a network/mask list eg flush +x.x.x.x/x -x.x.x.x/x" >&2
      echo "either in ${CONFFILE} or in ${SCRIPTNAME}" >&2

      ip route delete 0.0.0.0/1
      echo "default VPN gateway deleted" >&2
   else 
      IP=$(ip -4 addr show "${TUNSNX}" | awk '/inet/ { print $2 } ')

      [ -z "$IP" ] && die "do split only after VPN tunnel is up"

      for i in ${SPLIT}
      do
         case ${i::1} in

            f)
               ip route flush table main dev "${TUNSNX}"
               ;;

            +)
               ip route add "${i:1}" dev "${TUNSNX}" src "${IP}"
               ;;

            -)
               ip route delete "${i:1}" dev "${TUNSNX}" src "${IP}"
               ;;

            *)
               die "error in SPLIT format. If working in a previous version, SPLIT behaviour changed"
               ;;

         esac
      done
   fi
}


showStatus()
{  
   local VER

   if ! isCShellRunning
   then
      die "CShell not running"
   else
      echo "CShell running" 
   fi

   echo
   echo -n "System: "
   awk -v ORS= -F"=" '/^PRETTY_NAME/ { gsub("\"","");print $2" " } ' /etc/os-release
   echo -n "$(uname -m) "
   uname -r

   echo -n "Chroot: "
   doChroot /bin/bash --login -pf <<-EOF2 | awk -v ORS= -F"=" '/^PRETTY_NAME/ { gsub("\"","");print $2" " } '
	cat /etc/os-release
	EOF2

   doChroot /bin/bash --login -pf <<-EOF3
	/usr/bin/dpkg --print-architecture
	EOF3

   echo
   echo -n "SNX - installed              "
   doChroot snx -v 2> /dev/null | awk '/build/ { print $2 }'
   
   echo -n "SNX - available for download "
   if ! curl -k --silent --fail "https://${VPN}/SNX/CSHELL/snx_ver.txt" 2> /dev/null
   then
      curl -k --silent --fail "https://${VPN}/${SSLVPN}/SNX/CSHELL/snx_ver.txt" 2> /dev/null || echo "Could not get SNX download version" >&2
   fi

   echo
   if [[ -f "${CHROOT}/root/.cshell_ver.txt" ]]
   then
      echo -n "CShell - installed version      "
      cat "${CHROOT}/root/.cshell_ver.txt"
   fi

   echo -n "CShell - available for download "
   if ! curl -k --silent --fail "https://${VPN}/SNX/CSHELL/cshell_ver.txt" 2> /dev/null
   then
      curl -k --silent --fail "https://${VPN}/${SSLVPN}/SNX/CSHELL/cshell_ver.txt" 2> /dev/null || echo "Could not get CShell download version" >&2
   fi

   if [[ -f "${CHROOT}/usr/bin/cshell/cert/CShell_Certificate.crt" ]]
   then
      echo
      echo "CShell localhost self-signed CA certificate"
      echo
      openssl x509 -in "${CHROOT}/usr/bin/cshell/cert/CShell_Certificate.crt" -text | grep -E ", CN = |  Not [BA]"
   fi

   echo
   [[ -f "${CONFFILE}" ]] && cat "${CONFFILE}"

   echo
   IP=""
   IP=$(ip -4 addr show "${TUNSNX}" 2> /dev/null | awk '/inet/ { print $2 } ')

   echo -n "Linux  IP address: "
    ip a s |
    sed -ne '
        /127.0.0.1/!{
            s/^[ \t]*inet[ \t]*\([0-9.]\+\)\/.*$/\1/p
        }
    '

   echo

   if [[ -n "${IP}" ]]
   then
      echo "VPN on"
      echo
      echo "${TUNSNX} IP address: ${IP}"

      echo
      if curl --output /dev/null --silent --fail --noproxy '*' "${URL_VPN_TEST}"
      then
         echo "split tunnel VPN"
      else
         echo "full  tunnel VPN"
      fi
   else
      echo "VPN off"
   fi

   echo
   echo "VPN signatures"
   echo
   bash -c "cat ${CHROOT}/etc/snx/"'*.db' 2> /dev/null

   echo
   [[ "${RH}" -eq 1 ]] && resolvectl status
   echo
   cat /etc/resolv.conf
   echo
    
   VER=$(curl -k --silent --fail "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | jq -r ".tag_name")

   echo "current ${SCRIPTNAME} version     : ${VERSION}"

   [[ "${VER}" == "null" ]] || [[ -z "${VER}" ]] || echo "GitHub  ${SCRIPTNAME} version     : ${VER}"

   echo
   echo "${VPN} X.509 certificate" 
   echo | \
   openssl s_client -servername "${VPN}" -connect "${VPN}":443 2>/dev/null | \
   openssl x509 -text | awk '/^-----BEGIN CERTIFICATE/ {exit} {print}'
}


killCShell()
{
   if isCShellRunning
   then

      pkill -9 -f CShell 

      if ! isCShellRunning
      then
         echo "CShell stopped" >&2
      else
         die "Something is wrong. kill -9 did not kill CShell"
      fi

   fi
}


fixLinks()
{
   if [[ -f "$1" ]]
   then
      ln -sf "$1" "${CHROOT}/etc/resolv.conf"

      if ! readlink /etc/resolv.conf | grep "$1" &> /dev/null
      then
         ln -sf "$1" /etc/resolv.conf
      fi
   else
      if [[ "$( realpath "/etc/resolv.conf" )" == *"run"* ]]
      then
         echo -n "Using instead for chroot resolv.conf"  >&2
         realpath "/etc/resolv.conf" 
         ln -sf "$( realpath "/etc/resolv.conf" )" "${CHROOT}/etc/resolv.conf"
      else
         echo "if $1 does not exist, we cant use it to fix/share resolv.conf file between host and chroot" >&2
         echo "setting up chroot DNS as a copy of host" >&2
         echo "resolv.conf DNS servers given by VPN wont be mirrored from chroot to the host /etc/resolv.conf" >&2
         rm -f "${CHROOT}/etc/resolv.conf"
         cat /etc/resolv.conf > "${CHROOT}/etc/resolv.conf"
      fi
   fi
}


fixDNS()
{

   cd /etc || die "could not enter /etc"

   [[ "${DEB}" -eq 1 ]] && [[ "${DEEPIN}" -eq 0 ]] && fixLinks ../run/resolvconf/resolv.conf

   [[ "${RH}"        -eq 1 ]] && fixLinks ../run/systemd/resolve/stub-resolv.conf

   [[ "${SUSE}"      -eq 1 ]] && fixLinks ../run/netconfig/resolv.conf

   [[ "${ARCH}"      -eq 1 ]] && fixLinks ../run/NetworkManager/resolv.conf
   [[ "${GENTOO}"    -eq 1 ]] && fixLinks ../run/NetworkManager/resolv.conf
   [[ "${SLACKWARE}" -eq 1 ]] && fixLinks ../run/NetworkManager/resolv.conf
   [[ "${VOID}"      -eq 1 ]] && fixLinks ../run/NetworkManager/resolv.conf
   [[ "${DEEPIN}"    -eq 1 ]] && fixLinks ../run/NetworkManager/resolv.conf
}


doStart()
{
   if ! su - "${SUDO_USER}" -c "DISPLAY=${DISPLAY} xhost +local:"
   then
      echo "If there are not X11 desktop permissions, the VPN won't run" >&2
      echo "run this while logged in to the graphic console," >&2
      echo "or in a terminal inside the graphic console" >&2
      echo 
      echo "X11 auth not given" >&2
      echo "Please run as the X11/regular user:" >&2
      echo "xhost +si:local:" >&2
   fi


   fixDNS

   mountChrootFS


   if  isCShellRunning
   then
      killCShell
      echo "Trying to start it again..." >&2
   fi

   doChroot /bin/bash --login -pf <<-EOF4
	su -c "DISPLAY=${DISPLAY} /usr/bin/cshell/launcher" ${CSHELL_USER}
	EOF4

   if ! isCShellRunning
   then
      die "something went wrong. CShell daemon not launched." 
   else
      echo -e "\nAbra em seu browser este endereço, https://${VPN} para logar/startar a VPN" >&2
      echo >&2
      echo -e "\nCaso seja preciso, acesse o endereço https://localhost:14186/id para validar o certificado." >&2
      echo -e "\nSe não funcionar, abra o terminal, e execute ${SCRIPTNAME}\n\n" >&2
   fi
}


fixDNS2()
{

   [[ "${DEB}"  -eq 1 ]] && [[ "${DEEPIN}" -eq 0 ]] && resolvconf -u
   [[ "${SUSE}" -eq 1 ]] && netconfig update -f
   [[ "${RH}"   -eq 1 ]] && which authselect &>/dev/null && authselect apply-changes
}


doDisconnect()
{
   pgrep snx > /dev/null && doChroot /usr/bin/snx -d

   fixDNS2
}


doStop()
{
   doDisconnect

   killCShell
  
   umountChrootFS
}


doShell()
{
   mountChrootFS

   doChroot /bin/bash --login -pf

   if ! isCShellRunning
   then
      umountChrootFS
   fi
}

doRemoveChroot()
{
   doStop

   rm -rf "${CHROOT}"           &>/dev/null
   echo "${CHROOT} deleted"  >&2
}

doUninstall()
{
   doStop

   rm -f  "${XDGAUTO}"          &>/dev/null
   rm -rf "${CHROOT}"           &>/dev/null
   rm -f  "${INSTALLSCRIPT}"    &>/dev/null
   userdel -rf "${CSHELL_USER}" &>/dev/null
   groupdel "${CSHELL_GROUP}"   &>/dev/null

   FirefoxPolicy uninstall

   if [[ -f "${CONFFILE}" ]]
   then
      echo "${CONFFILE} not deleted. If you are not reinstalling do:" >&2
      echo "sudo rm -f ${CONFFILE}" >&2
      echo >&2
      echo "cat ${CONFFILE}" >&2
      cat "${CONFFILE}" >&2
      echo >&2
   fi

   echo "chroot+checkpoint software deleted" >&2
}


Upgrade() 
{
   doChroot /bin/bash --login -pf <<-EOF12
	apt update
	apt -y upgrade
        apt -y autoremove
	apt clean
	EOF12
}


selfUpdate() 
{
    local vpnsh
    local VER

    VER=$(curl -k --silent --fail "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | jq -r ".tag_name")
    echo "current version     : ${VERSION}"

    [[ "${VER}" == "null" ]] || [[ -z "${VER}" ]] && die "did not find any github release. Something went wrong"

    if [[ "${VER}" > "${VERSION}" ]]
    then
        echo "Found a new version of ${SCRIPTNAME}, updating myself..."

        vpnsh="$(mktemp)" || die "failed creating mktemp file"

        if curl -k --output "${vpnsh}" --silent --fail "https://github.com/${GITHUB_REPO}/releases/download/${VER}/vpn.sh" 
        then

           [[ "${INSTALLSCRIPT}" != "${SCRIPT}"  ]] && cp -f "${vpnsh}" "${SCRIPT}" && chmod a+rx "${SCRIPT}"

           [[ -f "${INSTALLSCRIPT}" ]] && cp -f "${vpnsh}" "${INSTALLSCRIPT}" && chmod a+rx "${INSTALLSCRIPT}"

           [[ -f "${PKGSCRIPT}" ]] && cp -f "${vpnsh}" "${PKGSCRIPT}" && chmod a+rx "${PKGSCRIPT}"

           rm -f "${vpnsh}"

           echo "script(s) updated to version ${VER}"
           exit 0
        else
           die "could not fetch new version"
        fi

    else
       die "Already the latest version."
    fi
}


PreCheck2()
{
   if [[ ! -f "${CHROOT}/usr/bin/cshell/launcher" ]]
   then


      if [[ "$1" != "selfupdate" ]]
      then
         if [[ -d "${CHROOT}" ]]
         then
            umountChrootFS

            if [[ "$1" != "uninstall" ]] && [[ "$1" != "rmchroot" ]]
            then
               die "Something went wrong. Correct or to reinstall, run: ./${SCRIPTNAME} uninstall ; ./${SCRIPTNAME} -i"
            fi

         else
            echo "To install the chrooted Checkpoint client software, run:" >&2

            if [[ -f "${CONFFILE}" ]]
            then
               die  "./${SCRIPTNAME} -i"
            else
               die  "./${SCRIPTNAME} -i --vpn=FQDN"
            fi
         fi
      fi
   fi
}

      
argCommands()
{
   PreCheck2 "$1"

   case "$1" in

      start)        doStart ;; 
      restart)      doStart ;;
      stop)         doStop ;;
      disconnect)   doDisconnect ;;
      fixdns)       fixDNS2 ;;
      split)        Split ;;
      status)       showStatus ;;
      shell)        doShell ;;
      uninstall)    doUninstall ;;
      rmchroot)     doRemoveChroot ;;
      upgrade)      Upgrade ;;
      selfupdate)   selfUpdate ;;
      selfdownload) curl -k --output "/tmp/vpn.sh" --silent --fail "https://raw.githubusercontent.com/${GITHUB_REPO}/main/vpn.sh" ;;
      *)            do_help ;;

   esac

}


preFlight()
{
   if [[ "${EUID}" -ne 0 ]] || [[ "${install}" -eq false ]]
   then
      exec sudo "$0" "${args[@]}"
   fi

   if  isCShellRunning 
   then
      die "CShell running. Before proceeding, run: ./${SCRIPTNAME} uninstall" 
   fi

   if [[ -d "${CHROOT}" ]]
   then
      umountChrootFS

      die "${CHROOT} present. Before install, run: ./${SCRIPTNAME} uninstall" 
   fi
}


needCentOSFix()
{
   if grep "^CentOS Linux release 8" /etc/redhat-release &> /dev/null
   then
      sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
      sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

      $DNF -y install epel-release || die "could not install epel-release"
   else
      if  grep "^CentOS Stream release" /etc/redhat-release &> /dev/null
      then
         $DNF -y install centos-stream-repos

         $DNF -y install epel-release || die "could not install epel-release. Fix it"
      else
         die "could not install epel-release"
      fi
   fi
}


GetCompileSlack()
{
   local SLACKBUILDREPOBASE
   local SLACKVERSION
   local SLACKBUILDREPO
   local DIR
   local pkg
   local BUILD
   local NAME
   local INFO
   local DOWNLOAD

   echo -e "\n\nInstalando na distro Slackware\n" >&2

   SLACKBUILDREPOBASE="https://slackbuilds.org/slackbuilds/"
   SLACKVERSION=$(awk -F" " ' { print $2 } ' /etc/slackware-version | tr -d "+" )
   SLACKBUILDREPO="${SLACKBUILDREPOBASE}/${SLACKVERSION}/"

   rm -f /tmp/*tgz
 
   pushd .

   DIR=$(mktemp -d -p . )
   mkdir -p "${DIR}" || die "could not create ${DIR}"
   cd "${DIR}" || die "could not enter ${DIR}"

   for pkg in "development/dpkg" "system/debootstrap" "system/jq"
   do
      NAME=${pkg##*/}

      if [[ ${NAME} != "debootstrap" ]]
      then
         which ${NAME} &>/dev/null && continue 
      fi

      pushd .
     
      BUILD="${SLACKBUILDREPO}${pkg}.tar.gz"
      curl -k -O "${BUILD}" --silent --fail || die "could not download ${BUILD}"

      tar -zxvf "${NAME}.tar.gz"
      cd "$NAME" || die "cannot cd ${NAME}"

      if [[ "${NAME}" == "debootstrap" ]]
      then
         DOWNLOAD="${SRC_BOOTSTRAP}"

         sed -i "s/^VERSION=.*/VERSION=${VER_BOOTSTRAP}/" ./${NAME}.SlackBuild

         sed -i 's/cd $PRGNAM-$VERSION/cd $PRGNAM/' ./${NAME}.SlackBuild
      else
         INFO="${SLACKBUILDREPO}${pkg}/${NAME}.info"
         curl -k -O "${INFO}" --silent --fail || die "could not download ${INFO}"

         DOWNLOAD=$(awk -F= ' /DOWNLOAD/ { gsub("\"", ""); print $2 } ' "${NAME}.info")
      fi

      curl -k -O "${DOWNLOAD}" --silent --fail || die "could not download ${DOWNLOAD}"

      ./${NAME}.SlackBuild
     
      popd || die "error restoring cwd [for]"
   done
 
   popd || die "error restoring cwd"

   rm -rf "${DIR}"

   installpkg /tmp/*tgz

   rm -f /tmp/*tgz
}


InstallDebootstrapDeb()
{
   if [[ "$1" == "force" ]] || ! which debootstrap &>/dev/null || [[ ! -e "/usr/share/debootstrap/scripts/${RELEASE}" ]]
   then
      curl -k --output "${DEB_FILE}" "${DEB_BOOTSTRAP}" --silent --fail || die "could not download ${DEB_BOOTSTRAP}"
      dpkg -i --force-all "${DEB_FILE}"
      rm -f "${DEB_FILE}"
   fi
}


installDebian()
{
   echo -e "\n\nInstalando na distro Debian/Ubuntu\n\n" >&2

   apt -y update


   apt -y install ca-certificates x11-xserver-utils jq curl dpkg debootstrap
   [[ ${DEEPIN} -eq 0 ]] && apt -y install resolvconf

   which dpkg &>/dev/null || die "failed installing dpkg"

   if grep '^ID=trisquel' /etc/os-release &>/dev/null
   then
      InstallDebootstrapDeb force
      echo "debootstrap from Trisquel overloaded. If you want it back, delete and reinstall package" >&2
   fi

   apt clean
}


installRedHat()
{
   local RHVERSION

   echo -e "\n\nInstalando na distro RedHat\n\n" >&2


   ! which dnf &>/dev/null && which yum &>/dev/null && DNF="yum"
   ! which dnf &>/dev/null && ! which yum &>/dev/null && which apt &>/dev/null && DNF="apt"

   $DNF -y install debootstrap

   if ! which debootstrap &>/dev/null
   then
      if grep -Evi "^Fedora|^Mageia|Mandriva|^PCLinuxOS" /etc/redhat-release &> /dev/null
      then
         if grep -E "^REDHAT_SUPPORT_PRODUCT_VERSION|^ORACLE_SUPPORT_PRODUCT_VERSION|^MIRACLELINUX_SUPPORT_PRODUCT_VERSION" /etc/os-release &> /dev/null
         then
            RHVERSION=$(awk -F= ' /_SUPPORT_PRODUCT_VERSION/ { gsub("\"", ""); print $2 } ' /etc/os-release | sed 's/[^0-9].*//;2,$d' )
            $DNF -y install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${RHVERSION}.noarch.rpm"
         else
            $DNF -y install epel-release || needCentOSFix
         fi
      else
         if grep "^Mageia" /etc/redhat-release &> /dev/null
         then
            $DNF -y install NetworkManager
         fi
      fi
   fi

   $DNF -y install ca-certificates jq curl debootstrap

   if ! $DNF -y install dpkg
   then
      grep "OpenMandriva Lx" /etc/redhat-release &> /dev/null && $DNF -y install http://abf-downloads.openmandriva.org/4.3/repository/x86_64/unsupported/release/dpkg-1.21.1-1-omv4050.x86_64.rpm http://abf-downloads.openmandriva.org/4.3/repository/x86_64/unsupported/release/perl-Dpkg-1.21.1-1-omv4050.noarch.rpm
   fi


   if [[ ! -f "/usr/bin/xhost" ]]
   then
      $DNF -y install xorg-x11-server-utils
      $DNF -y install xhost
   fi
   $DNF clean all
}


installArch()
{
   echo -e "\n\nInstalando na distro Arch\n\n" >&2



   if ! pacman --needed -Syu ca-certificates xorg-xhost jq curl dpkg debootstrap
   then
      packman-key --populate
      pacman --needed -Syu ca-certificates xorg-xhost jq curl dpkg debootstrap
   fi
   pacman --needed -Syu firefox

}


installSUSE()
{
   local PACKAGEKIT

   echo -e "\n\nInstalando na distro SUSE\n\n" >&2


   if systemctl is-active --quiet packagekit
   then
      PACKAGEKIT=true
      systemctl stop --quiet packagekit
   fi

   zypper ref

   zypper -n install ca-certificates jq curl dpkg xhost dnsmasq

   which dpkg &>/dev/null || die "could not install software"

   zypper -n install debootstrap

   zypper clean

   InstallDebootstrapDeb

   [[ ${PACKAGEKIT} -eq true ]] && systemctl start --quiet packagekit

}


installVoid()
{
   echo -e "\n\nInstalando na distro Void\n\n" >&2

   xbps-install -yu xbps
   xbps-install -ySu

   xbps-install -yS void-repo-nonfree void-repo-multilib-nonfree
   xbps-install -yS ca-certificates xhost jq curl debootstrap dpkg openresolv
}


installGentoo()
{
   echo -e "\n\nInstalando na distro Gentoo\n\n" >&2

   emaint --allrepos sync || die "did not sync all repos"

   emerge --ask --verbose --update --deep --changed-use --with-bdeps=y  --keep-going=y --backtrack=100  @world || die "did not manage to update the system. Fix this before calling ${SCRIPTNAME} again. Your image might be too old, or you might to have to use  emerge --deselect <name_of_package> plus emerge -a --depclean"

   emerge --ask --oneshot --verbose sys-apps/portage

   emerge -atv ca-certificates xhost app-misc/jq debootstrap dpkg

   emerge --ask --verbose --depclean

}


installPackages()
{

   [[ "${DEB}"       -eq 1 ]] && installDebian

   [[ "${RH}"        -eq 1 ]] && installRedHat

   [[ "${ARCH}"      -eq 1 ]] && installArch

   [[ "${SUSE}"      -eq 1 ]] && installSUSE

   [[ "${VOID}"      -eq 1 ]] && installVoid

   [[ "${GENTOO}"    -eq 1 ]] && installGentoo

   [[ "${SLACKWARE}" -eq 1 ]] && GetCompileSlack


   InstallDebootstrapDeb

   if ! which dpkg &> /dev/null || ! which debootstrap &> /dev/null
   then
      die "something went wrong installing software"
   fi
   
}


fixRHDNS()
{
   local counter

   if [[ "${RH}" -eq 1 ]] && [[ ! -f "/run/systemd/resolve/stub-resolv.conf" ]] && which systemctl &> /dev/null
   then

      if [[ ! -f "/usr/lib/systemd/systemd-resolved" ]]
      then	    
         echo "one of the next dnf will fail. Only is an issue if both fail" >&2
         $DNF -y install libnss-resolve
         $DNF -y install systemd-resolved 
      fi

      systemctl unmask systemd-resolved &> /dev/null
      systemctl start  systemd-resolved
      systemctl enable systemd-resolved

      counter=0
      while ! systemctl is-active systemd-resolved &> /dev/null
      do
         sleep 2
         (( counter=counter+1 ))
         [[ "$counter" -eq 30 ]] && die "systemd-resolved not going live"
      done

      [[ ! -f "/run/systemd/resolve/stub-resolv.conf" ]] && die "Something went wrong activating systemd-resolved"

      sed -i '/NMCONTROLLED/d' /etc/sysconfig/network-scripts/ifcfg-*  &>/dev/null
      sed -i '$ a NMCONTROLLED="yes"' /etc/sysconfig/network-scripts/ifcfg-*  &>/dev/null

      cd /etc || die "was not able to cd /etc"

      ln -sf ../run/systemd/resolve/stub-resolv.conf resolv.conf

      systemctl reload NetworkManager

      counter=0
      while ! systemctl is-active NetworkManager &> /dev/null
      do 
         sleep 4
         (( counter=counter+1 ))
         [[ "$counter" -eq 20 ]] && die "NetworkManager not going live"
      done
   fi
}


fixSUSEDNS()
{
   if [[ "${SUSE}" -eq 1 ]] && grep -v ^NETCONFIG_DNS_FORWARDER=\"dnsmasq\" /etc/sysconfig/network/config &> /dev/null
   then

      sed -i 's/^NETCONFIG_DNS_FORWARDER=.*/NETCONFIG_DNS_FORWARDER="dnsmasq"/g' /etc/sysconfig/network/config

      cd /etc || die "was not able to cd /etc"

      ln -sf ../run/netconfig/resolv.conf resolv.conf

      systemctl restart network
   fi
}


checkDNS()
{
   getent ahostsv4 "${VPN}"  &> /dev/null
   
   if ! getent ahostsv4 "${VPN}" &> /dev/null
   then
      fixDNS2

      if ! getent ahostsv4 "${VPN}" &> /dev/null
      then
         echo "DNS problems after installing resolvconf?" >&2
         echo "Not resolving ${VPN} DNS" >&2
         echo "Relaunch ${SCRIPTNAME} for possible timeout issues" >&2
         die "Otherwise fix or reboot to fix" 
      fi	   
   fi
}


createChroot()
{
   echo -e "\nInstalação iniciada, por favor aguarde..." >&2
   echo -e "\nEm alguns casos, o processo de intalação demora ou trava, isto porque o debootstrap precisa trocar informações com o repositório Debian." >&2
   echo -e "\nSe travar, execute um Ctrl + C para cancelar a instalação e tentar novamente.\n" >&2

   mkdir -p "${CHROOT}" || die "could not create directory ${CHROOT}"

   chmod 755 "${CHROOT}"

   if ! debootstrap --no-check-gpg --variant="${VARIANT}" --arch i386 "${RELEASE}" "${CHROOT}" "${DEBIANREPO}"
   then
      echo "chroot ${CHROOT} unsucessful creation" >&2
      die "run\nsudo rm -rf ${CHROOT}\n and do it again" 
   fi
}


createCshellUser()
{
   getent group "^${CSHELL_GROUP}:" &> /dev/null || groupadd --gid "${CSHELL_GID}" "${CSHELL_GROUP}" 2>/dev/null ||true

   if ! getent passwd "^${CSHELL_USER}:" &> /dev/null 
   then
      useradd \
            --uid "${CSHELL_UID}" \
            --gid "${CSHELL_GID}" \
            --no-create-home \
            --home "${CSHELL_HOME}" \
            --shell "/bin/false" \
            "${CSHELL_USER}" 2>/dev/null || true
   fi
   test -d "${CSHELL_HOME}" || mkdir -p "${CSHELL_HOME}"
   chown -R "${CSHELL_USER}":"${CSHELL_GROUP}" "${CSHELL_HOME}"
   chmod -R u=rwx,g=rwx,o= "$CSHELL_HOME"
}


buildFS()
{
   cd "${CHROOT}" >&2 || die "could not chdir to ${CHROOT}" 

   mkdir -p "tmp/.X11-unix"

   mkdir -p "${CHROOT}/${CSHELL_HOME}/.config" || die "couldn not mkdir ${CHROOT}/${CSHELL_HOME}/.config"

   echo "TZ=${TZ}; export TZ" >> root/.profile

   rm -f snx_install.sh cshell_install.sh 2> /dev/null

   if curl -k -O --fail --silent "https://${VPN}/SNX/INSTALL/snx_install.sh"
   then 
      curl -O -k --fail --silent "https://${VPN}/SNX/INSTALL/cshell_install.sh" || die "could not download cshell_install.sh" 
      curl -k --fail --silent "https://${VPN}/SNX/CSHELL/cshell_ver.txt" 2> /dev/null > root/.cshell_ver.txt 
   else
      curl -k -O --silent --fail "https://${VPN}/${SSLVPN}/SNX/INSTALL/snx_install.sh" || die "could not download snx_install.sh" 
      curl -k -O --silent --fail "https://${VPN}/${SSLVPN}/SNX/INSTALL/cshell_install.sh" || die "could not download cshell_install.sh" 
      curl -k --silent --fail "https://${VPN}/${SSLVPN}/SNX/CSHELL/cshell_ver.txt" 2> /dev/null > root/.cshell_ver.txt
   fi

   mv cshell_install.sh "${CHROOT}/root"
   mv snx_install.sh "${CHROOT}/root"

   cat <<-EOF5 > sbin/modprobe
	#!/bin/bash
	exit 0
	EOF5

   mv usr/bin/who usr/bin/who.old
   cat <<-EOF6 > usr/bin/who
	#!/bin/bash
	echo -e "${CSHELL_USER}\t:0"
	EOF6

   cat <<-EOF7 > etc/hosts
	127.0.0.1 localhost
	${VPNIP} ${VPN}
	EOF7

   if [[ -n "${HOSTNAME}" ]]
   then
      echo -e "\n127.0.0.1 ${HOSTNAME}" >> etc/hosts

      if ! grep "${HOSTNAME}" /etc/hosts &> /dev/null
      then
         echo -e "\n127.0.0.1 ${HOSTNAME}" >> /etc/hosts
      fi
   fi

   if [[ -n "${CHROOTPROXY}" ]]
   then
      cat <<-EOF8 > etc/apt/apt.conf.d/02proxy
	Acquire::http::proxy "${CHROOTPROXY}";
	Acquire::ftp::proxy "${CHROOTPROXY}";
	Acquire::https::proxy "${CHROOTPROXY}";
	EOF8
   fi

   echo "${CHROOT}" > etc/debian_chroot

   if [[ ${JAVA8} -eq true ]]
   then
      echo 'deb http://security.debian.org/ stretch/updates main' > etc/apt/sources.list.d/stretch.list
   fi

   cat <<-EOF9 > root/chroot_setup.sh
	#!/bin/bash
	# "booleans"
	true=0
	false=1
	# --oldjava
        JAVA8=${JAVA8}

	# creates cShell user
	# creates group 
	addgroup --quiet --gid "${CSHELL_GID}" "${CSHELL_GROUP}" 2>/dev/null ||true
	# creates user
	adduser --quiet \
	        --uid "${CSHELL_UID}" \
	        --gid "${CSHELL_GID}" \
	        --no-create-home \
	        --disabled-password \
	        --home "${CSHELL_HOME}" \
	        --gecos "Checkpoint Agent" \
	        "${CSHELL_USER}" 2>/dev/null || true

	# adjusts file and directory permissions
	# creates homedir 
	test  -d "${CSHELL_HOME}" || mkdir -p "${CSHELL_HOME}"
	chown -R "${CSHELL_USER}":"${CSHELL_GROUP}" "${CSHELL_HOME}"
	chmod -R u=rwx,g=rwx,o= "$CSHELL_HOME"

	# creates a who apt diversion for the fake one not being replaced
	# by security updates inside chroot
	dpkg-divert --divert /usr/bin/who.old --no-rename /usr/bin/who

	# needed packages
	apt -y install libstdc++5 libx11-6 libpam0g libnss3-tools procps net-tools bzip2

        # --oldjava
	if [[ ${JAVA8} -eq true ]]
	then
	   # needed package
           # update to get metadata of stretch update repository
           # so we can get OpenJDK 8+dependencies
           # update intentionally done only after installing other packages
	   apt -y update
	   apt -y install openjdk-8-jdk 
	else
	   # needed package
	   apt -y install openjdk-11-jre
	fi

	# clean APT chroot cache
	apt clean
	
	# install SNX and CShell
	/root/snx_install.sh
	echo "Installing CShell" >&2
	DISPLAY="${DISPLAY}" PATH=/nopatch:"${PATH}" /root/cshell_install.sh 
	
	exit 0
	EOF9

        mkdir nopatch

	cat <<-'EOF18' > nopatch/certutil
	#!/bin/bash
	if [[ "$1" == "-H" ]]
	then
	   exit 1
	else
	   exit 0
	fi
	EOF18

   ln -s ../sbin/modprobe nopatch/xhost
   ln -s ../sbin/modprobe nopatch/xterm

   mkdir -p "home/${CSHELL_USER}/.mozilla/firefox/3ui8lv6m.default-release"
   touch "home/${CSHELL_USER}/.mozilla/firefox/3ui8lv6m.default-release/cert9.db"
   cat <<-'EOF16' > "home/${CSHELL_USER}/.mozilla/firefox/installs.ini"
	Path=3ui8lv6m.default-release
	Default=3ui8lv6m.default-release
	EOF16

   ( 
   cd "home/${CSHELL_USER}/.mozilla/firefox/" || die "was not able to cd home/${CSHELL_USER}/.mozilla/firefox/"
   ln -s installs.ini profiles.ini
   )

   chmod a+rx usr/bin/who sbin/modprobe root/chroot_setup.sh root/snx_install.sh root/cshell_install.sh nopatch/certutil

}


FstabMount()
{
   cat <<-EOF10 > etc/fstab
	/tmp            ${CHROOT}/tmp           none bind 0 0
	/dev            ${CHROOT}/dev           none bind 0 0
	/dev/pts        ${CHROOT}/dev/pts       none bind 0 0
	/sys            ${CHROOT}/sys           none bind 0 0
	/var/log        ${CHROOT}/var/log       none bind 0 0
	/run            ${CHROOT}/run           none bind 0 0
	/proc           ${CHROOT}/proc          proc defaults 0 0
	/dev/shm        ${CHROOT}/dev/shm       none bind 0 0
	/tmp/.X11-unix  ${CHROOT}/tmp/.X11-unix none bind 0 0
	EOF10

   mountChrootFS
}


XDGAutoRun()
{
   if [[ -d "$(dirname ${XDGAUTO})" ]]
   then
      cat > "${XDGAUTO}" <<-EOF11
	[Desktop Entry]
	Type=Application
	Name=cshell
	Exec=sudo "${INSTALLSCRIPT}" -s -c "${CHROOT}" start
	Icon=
	Comment=
	X-GNOME-Autostart-enabled=true
	X-KDE-autostart-after=panel
	X-KDE-StartupNotify=false
	StartupNotify=false
	EOF11
      
      echo "Adicionado auto-start em modo GUI" >&2
      echo

      echo "Para que o script seja executado, modifique seu arquivo /etc/sudoers para não pedir senha sudo:" >&2
      echo "Conforme o exemplo abaixo:" >&2

      if [[ -n "${SUDO_USER}" ]]
      then
         if ingroup sudo "${SUDO_USER}"
         then
            echo >&2
            echo "%sudo	ALL=(ALL:ALL) NOPASSWD:ALL" >&2
            echo "#ou: " >&2
            echo "%sudo	ALL=(ALL:ALL) NOPASSWD: ${INSTALLSCRIPT}" >&2
         fi
         if ingroup wheel "${SUDO_USER}"
         then
            echo >&2
            echo "%wheel	ALL=(ALL:ALL) NOPASSWD:ALL" >&2
            echo "#ou: " >&2
            echo "%wheel	ALL=(ALL:ALL) NOPASSWD: ${INSTALLSCRIPT}" >&2
         fi

         echo "#ou: " >&2
         echo "${SUDO_USER}	ALL=(ALL:ALL) NOPASSWD:ALL" >&2
         echo "#ou: " >&2
         echo "${SUDO_USER}	ALL=(ALL:ALL) NOPASSWD: ${INSTALLSCRIPT}" >&2
      fi

      echo >&2

      if ! grep "${INSTALLSCRIPT}" /etc/sudoers &>/dev/null
      then
         echo
         echo -e "\n%sudo       ALL=(ALL:ALL) NOPASSWD: ${INSTALLSCRIPT}" >> /etc/sudoers
         echo "%sudo       ALL=(ALL:ALL) NOPASSWD: ${INSTALLSCRIPT}" >&2
         echo "added to /etc/sudoers" >&2
      fi

   else
      echo "Was not able to create XDG autorun desktop entry for CShell" >&2
   fi
}


createConfFile()
{
    mkdir -p "$(dirname "${CONFFILE}")" 2> /dev/null

    cat <<-EOF13 > "${CONFFILE}"
	VPN="${VPN}"
	VPNIP="${VPNIP}"
	SPLIT="${SPLIT}"
	CHROOT="${CHROOT}"
	EOF13

    [[ "${SSLVPN}" != "sslvpn" ]] && echo "SSLVPN=\"${SSLVPN}\"" >> "${CONFFILE}"
}


chrootEnd()
{

   local ROOTHOME

   doChroot /bin/bash --login -pf <<-EOF15
	/root/chroot_setup.sh
	EOF15

   if isCShellRunning && [[ -f "${CHROOT}/usr/bin/snx" ]]
   then
      ROOTHOME="${CHROOT}/root"
      rm -f "${ROOTHOME}/chroot_setup.sh" "${ROOTHOME}/cshell_install.sh" "${ROOTHOME}/snx_install.sh" 

      cp "${SCRIPT}" "${INSTALLSCRIPT}"
      chmod a+rx "${INSTALLSCRIPT}"

      createConfFile

      XDGAutoRun

      echo "!!! INSTALAÇÃO CONCLUÍDA !!!." >&2
      echo "${SCRIPT} copiado para ${INSTALLSCRIPT}" >&2
      echo >&2

      FirefoxPolicy install

      echo "Abra seu navegador em https://localhost:14186/id se for o primeiro acesso desta máquina, para aceitar o certificado em localhost." >&2
      echo
      echo "Depois, abra o navegador em https://${VPN} para logar na VPN" >&2
      echo "Se não funcionar, execute ${SCRIPTNAME} no terminal." >&2
      echo
      echo "fazendo a primeira reinicialização" >&2
      doStart
   else
      umountChrootFS

      die "Something went wrong. Chroot unmounted. Fix it or delete $CHROOT and run this script again" 

   fi
}


InstallChroot()
{
   preFlight
   installPackages
   fixRHDNS
   fixSUSEDNS
   checkDNS
   createChroot
   createCshellUser
   buildFS
   FstabMount
   fixDNS
   chrootEnd
}

#echo -e "\n\n!!! AGUARDE UM MOMENTO !!!\n"

#apt install unzip -y &>/dev/null
#sudo apt-get install openjdk-11-jdk -y &>/dev/null
#wget -c -q -P /tmp https://raw.githubusercontent.com/2mesistemas/vm/main/CSHELL.zip
#wget -c -q -P /tmp https://raw.githubusercontent.com/2mesistemas/vm/main/cshell.zip
#sudo rm -R /tmp/CSHELL &>/dev/null
#sudo rm -R /usr/bin/cshell &>/dev/null
#sudo unzip /tmp/CSHELL.zip -d /tmp &>/dev/null
#sudo unzip /tmp/cshell.zip -d /tmp &>/dev/null
#sudo cp -R /tmp/cshell /usr/bin/ &>/dev/null
#sudo rm -R /tmp/cshell &>/dev/null
#sudo rm /tmp/cshell.zip &>/dev/null
#sudo rm /tmp/CSHELL.zip &>/dev/null

main()
{
   doGetOpts "$@"

   shift $((OPTIND-1))

   PreCheck "$1"

   if [[ "${install}" -eq false ]]
   then

      argCommands "$1"
   else
      InstallChroot
   fi

   exit 0
}

main "$@"
