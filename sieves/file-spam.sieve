# Global "after" script: file anything rspamd marked as spam into Junk.
#
# The X-Spam header comes from rspamd's milter_headers module, which adds
# it when the message reaches the add_header action.

require [ "fileinto" ];

if header :is "X-Spam" "Yes" {
  fileinto "Junk";
  stop;
}
