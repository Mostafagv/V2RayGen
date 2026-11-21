- working option: `curl https://raw.githubusercontent.com/Mostafagv/V2RayGen/main/V2RayGen.py | sudo python3 - --vless --tcp --reality --vision` </br>

- working option with custom SNI: `curl https://raw.githubusercontent.com/Mostafagv/V2RayGen/main/V2RayGen.py | sudo python3 - --vless --tcp --reality --vision --sni www.cloudflare.com --reality-dest www.cloudflare.com:443` </br>

## Speed: enable BBR on the server

Run this once on the server (Linux kernel 4.9+). It switches TCP congestion control to BBR, which usually gives much better speed on long or lossy routes. It persists across reboots and is safe to run more than once:

```bash
printf "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n" | sudo tee /etc/sysctl.d/99-bbr.conf >/dev/null && sudo sysctl --system >/dev/null && sysctl net.ipv4.tcp_congestion_control
```

The last line should print `net.ipv4.tcp_congestion_control = bbr`. No need to regenerate the link or restart Xray; new connections use BBR right away.
