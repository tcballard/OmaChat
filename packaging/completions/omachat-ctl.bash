_omachat_ctl() {
  local current="${COMP_WORDS[COMP_CWORD]}"
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W '--socket status fingerprint join leave send join-room leave-room rooms room-members hosted-conversations hosted-history hosted-mark-read hosted-open-dm hosted-claim-handle hosted-resolve-handle hosted-create-workspace hosted-create-channel hosted-add-member panic' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == status || ${COMP_WORDS[1]} == rooms || ${COMP_WORDS[1]} == room-members || ${COMP_WORDS[1]} == hosted-conversations || ${COMP_WORDS[1]} == hosted-open-dm || ${COMP_WORDS[1]} == hosted-resolve-handle ]]; then
    COMPREPLY=($(compgen -W '--json' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == hosted-history ]]; then
    COMPREPLY=($(compgen -W '--before --limit --json' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == join-room ]]; then
    COMPREPLY=($(compgen -W '--invite' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == fingerprint ]]; then
    COMPREPLY=($(compgen -W '--qr' -- "$current"))
  elif [[ ${COMP_WORDS[1]} == panic ]]; then
    COMPREPLY=($(compgen -W '--confirm' -- "$current"))
  fi
}
complete -F _omachat_ctl omachat-ctl
