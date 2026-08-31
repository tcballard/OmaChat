_omachat() { COMPREPLY=($(compgen -W '--socket --version' -- "${COMP_WORDS[COMP_CWORD]}")); }
complete -F _omachat omachat
