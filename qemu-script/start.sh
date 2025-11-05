swtpm socket \
  --tpm2 \
  --tpmstate dir=~/vm-tpm \
  --ctrl type=unixio,path=/tmp/swtpm-sock \
  --daemon

./qemu-script/cs423-q
