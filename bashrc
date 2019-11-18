# ~/.bashrc: executed by bash(1) for non-login shells.
# This script is written to support multiple *nix flavors.
# If you use a single build, feel free to remove the "fluff" on your system

#Uncomment to set shell for close after 240 seconds
#TMOUT=240

case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000
HISTTIMEFORMAT='%Y%m%d_%H%M%S_%zUTC '

shopt -s histappend
shopt -s checkwinsize

if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

case "$TERM" in
    xterm-color) color_prompt=yes;;
esac

force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        color_prompt=yes
    else
        color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias dir='dir --color=auto'
    alias vdir='vdir --color=auto'

    alias grep='grep --color'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
    alias ls='ls -G --color=auto'
    alias ll='ls -alF --color=auto'
    alias la='ls -AalhG --color=auto'
    alias lg='ls -AalhG --color=auto |grep $1'
    alias l='ls -CF --color=auto'
    alias el='sudo $(history -p \!\!)'
    alias level='echo $SHLVL'
fi

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi


function mkcd() {
    mkdir -p "$@"
    cd "$@"
}

# Chrome - User
if [ ! -d ~/.chrome_user ]; then
    mkdir ~/.chrome_user
fi
alias chromium="chromium --user-data-dir ~/.chrome_user"

CURDATE=`date '+%Y%m%d_%H%M%S.%N_%Z'`

# note: comment or uncomment as required for os
function my_ip {
#    /sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'
    /sbin/ifconfig eth0 | grep 'inet ' | awk '{ print $2}'
#    ipconfig getifaddr en0
}
if [ ! -d $HOME/logs ]; then
    mkdir $HOME/logs 2> /dev/null
fi

function mount_tools() {
    TOOLSDIR="/tools"
    if [ -f "$HOME/.toolspw" ]; then
        mountphrase=$(cat ${HOME}/.toolspw)
    else
        echo -n "Mount passphrase: "
        read -s mountphrase
    fi
    printf "%s" "${mountphrase}" | ecryptfs-add-passphrase > /tmp/tmp.txt
    sig=`tail -1 /tmp/tmp.txt | awk '{print $6}' | sed 's/\[//g' | sed 's/\]//g'`
    rm -f /tmp/tmp.txt
    mount -t ecryptfs -o key=passphrase:passphrase_passwd=${mountphrase},no_sig_cache=yes,verbose=no,ecryptfs_fnek_sig=${sig},ecryptfs_sig=${sig},ecryptfs_cipher=aes,ecryptfs_key_bytes=16,ecryptfs_passthrough=no,ecryptfs_enable_filename_crypto=yes $TOOLSDIR $TOOLSDIR
    unset mountphrase
}

alias unmount_tools="umount /tools"


function mount_data() {
    DATADIR="/data"
    if [ -d "/data" ]; then
        echo "/data exist"
    else
        echo "Creating /data"
        mkdir "/data"
    fi
    if [ -f "$HOME/.datapw" ]; then
        mountphrase=$(cat ${HOME}/.datapw)
    else
        echo -n "Mount passphrase: "
        read -s mountphrase
    fi
    printf "%s" "${mountphrase}" | ecryptfs-add-passphrase > /tmp/tmp.txt
    sig=`tail -1 /tmp/tmp.txt | awk '{print $6}' | sed 's/\[//g' | sed 's/\]//g'`
    rm -f /tmp/tmp.txt
    mount -t ecryptfs -o key=passphrase:passphrase_passwd=${mountphrase},no_sig_cache=yes,verbose=no,ecryptfs_fnek_sig=${sig},ecryptfs_sig=${sig},ecryptfs_cipher=aes,ecryptfs_key_bytes=16,ecryptfs_passthrough=no,ecryptfs_enable_filename_crypto=yes $DATADIR $DATADIR
    unset mountphrase
    if [ -d "/data/admin" ]; then
        ls /data
    else
        mkdir /data/admin /data/osint /data/recon /data/targets /data/screeshots /data/payloads /data/logs
    fi
}

alias unmount_data="umount /data"


function enable_teamserver() {
    echo "Make sure to set your parameters in /etc/default/teamserver"
    ln -s /lib/systemd/system/teamserver.service /etc/systemd/system/teamserver.service
    ln -s /lib/systemd/system/teamserver.service /etc/systemd/system/multi-user.target.wants/teamserver.service
    /bin/systemctl daemon-reload
    echo "To start, use 'systemctl start teamserver'"
}

function disable_teamserver() {
    systemctl stop teamserver
    rm /etc/systemd/system/teamserver.service /etc/systemd/system/multi-user.target.wants/teamserver.service
    /bin/systemctl daemon-reload
}

alias ext_ip="curl ifconfig.me"

function win_shutdown() {
    net rpc shutdown -I $1 -U $2%$3
}

alias netstati="lsof -P -i -n"

function termss() {
    local dt=$(date '+%Y%m%d_%H%M%S.%N_%Z')
    $1 | /usr/bin/convert -font "FreeMono" label:@- $HOME/logs/screenshots/${dt}_terminal_screenshot.png
}

function start_capture() {
    local pid=$HOME/logs/pcaps/current.pid
    if [ -f $pid ]; then
        if pgrep -F $pid; then
            echo "tcpdump is currently running for this user. Please stop it first."
            return
        fi
    fi
    [ ! -d $HOME/logs/pcaps ] && mkdir -p $HOME/logs/pcaps
    local dt=$(date '+%Y%m%d_%H%M%S.%N_%Z')
    /usr/bin/nohup tcpdump -i $1 -s0 -v -w $HOME/logs/pcaps/${dt}_capture_$1.pcap > /dev/null 2>&1 & echo $! > $pid
    echo "tcpdump started."
}

function stop_capture() {
    local pid=$HOME/logs/pcaps/current.pid
    if [ -f $pid ]; then
        if pgrep -F $pid; then
            kill -15 $(cat $pid)
            echo "tcpdump stopped."
            return
        fi
    else
        echo "tcpdump is not currently running."
    fi
}

[ ! -d $HOME/logs/screenshots ] && mkdir -p $HOME/logs/screenshots
[ ! -d $HOME/logs/terminals ] && mkdir -p $HOME/logs/terminals

# Colors
BLACK=$(tput setaf 0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
WHITE=$(tput setaf 7)
BRIGHT=$(tput bold)
NORMAL=$(tput sgr0)
BLINK=$(tput blink)
REVERSE=$(tput smso)
UNDERLINE=$(tput smul)

PS1="\n\[$WHITE\]╭ [\$(if [[ \$? == 0 ]]; then echo \"\[$GREEN\]✓\"; else echo \"\[$RED\]✕\"; fi) \[$WHITE\]\[$YELLOW\]\D{%Y%m%d_%H%M%S_%zUC} \[$WHITE\]\u@\h \[${CYAN}\]$(my_ip)\[$BLUE\]: \[$WHITE\]]\n├ [\[$GREEN\]\w\[$WHITE\]]\n\[$WHITE\]╰ \$ "

array=("gnome-terminal-" "gnome-terminal" "tmux" "termin" "terminal" "x-term" "term" "xterm" "konsole" "lxterm" "uxterm" "xterm-256color" "xfce4-terminal" "sudo")  
search_string=`basename $(ps -f -p $PPID -o comm=)` 
match=$(echo "${array[@]:0}" | grep -o $search_string)  

if [[ $TERM == "xterm"* ]] && [[ ! -z $match ]]; then
    logname="${HOME}/logs/terminals/${CURDATE}.terminal.log"
    printf "This is a logged terminal session....\n"
    script -f ${logname}.raw
    cat ${logname}.raw | perl -pe 's/\e([^\[\]]|\[.*?[a-zA-Z]|\].*?\a)//g' | col -b > ${logname}
    exit
fi


