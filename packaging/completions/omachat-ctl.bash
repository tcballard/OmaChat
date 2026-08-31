_omachat_ctl() {
  local current="${COMP_WORDS[COMP_CWORD]}"
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W '--socket status fingerprint join leave send panic' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == status ]]; then
    COMPREPLY=($(compgen -W '--json' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == fingerprint ]]; then
    COMPREPLY=($(compgen -W '--qr' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == panic ]]; then
    COMPREPLY=($(compgen -W '--confirm' -- "$current"))
  fi
}
complete -F _omachat_ctl omachat-ctl
