# Sender

Example usage with `sox` and `pv`:

`sox -S "example.wav" -r 44100 -b 16 -e signed-integer -c 2 -t raw - | pv -q -L 176400 | ./sikradio-sender -a [receiver_address] -n "Radio Example"`

# Receiver

Example usage with `play`:

`./sikradio-receiver -a [sender_address] | play -t raw -c 2 -r 44100 -b 16 -e signed-integer --buffer 32768 -`