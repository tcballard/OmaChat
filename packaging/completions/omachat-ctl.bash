_omachat_ctl() {
  local current="${COMP_WORDS[COMP_CWORD]}"
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W '--socket status fingerprint join leave send join-room leave-room rooms panic' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == status || ${COMP_WORDS[1]} == rooms ]]; then
    COMPREPLY=($(compgen -W '--json' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == join-room ]]; then
    COMPREPLY=($(compgen -W '--invite' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == fingerprint ]]; then
    COMPREPLY=($(compgen -W '--qr' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == panic ]]; then
    COMPREPLY=($(compgen -W '--confirm' -- "$current"))
  fi
}
complete -F _omachat_ctl omachat-ctl
