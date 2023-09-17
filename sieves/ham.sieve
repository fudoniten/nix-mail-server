require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];

if environment :matches "imap.mailbox" "*" {
  set "mailbox" "${1}";
}

if string "${mailbox}" "Trash" {
  stop;
}

if string "${mailbox}" "Junk" {
  stop
}

if environment :matches "imap.user" "*" {
  set "username" "${1}";
}

pipe :copy "rspamd_learn_ham" [ "${username}" ];
