- working option: `curl https://raw.githubusercontent.com/Mostafagv/V2RayGen/main/V2RayGen.py | sudo python3 - --vless --tcp --reality --vision` </br>

- working option with custom SNI: `curl https://raw.githubusercontent.com/Mostafagv/V2RayGen/main/V2RayGen.py | sudo python3 - --vless --tcp --reality --vision --sni www.cloudflare.com --reality-dest www.cloudflare.com:443` </br>

## Speed: enable BBR on the server

Run this once on the server (Linux kernel 4.9+). It switches TCP congestion control to BBR, which usually gives much better speed on long or lossy routes. It persists across reboots and is safe to run more than once:

```bash
printf "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n" | sudo tee /etc/sysctl.d/99-bbr.conf >/dev/null && sudo sysctl --system >/dev/null && sysctl net.ipv4.tcp_congestion_control
```

The last line should print `net.ipv4.tcp_congestion_control = bbr`. No need to regenerate the link or restart Xray; new connections use BBR right away.

## DigitalOcean: create and manage servers from your computer

`DOManager.py` runs on your own machine (Python 3, no extra packages). It creates DigitalOcean droplets, enables BBR and runs the VLESS REALITY command above on them at first boot, and fetches the generated links over SSH.

One-time setup:

1. Have an SSH key: `ssh-keygen -t ed25519` (it is uploaded to DigitalOcean automatically on first `create`).
2. Create an API token at https://cloud.digitalocean.com/account/api/tokens. A custom-scoped token needs: `droplet` (create, read, update, delete), `regions:read`, `sizes:read`, `ssh_key` (create, read), `tag:create`, `actions:read`.
3. Store it **outside the repo**, either as an environment variable or in a private file:

```bash
mkdir -p ~/.config/v2raygen && chmod 700 ~/.config/v2raygen
printf 'DIGITALOCEAN_TOKEN=dop_v1_...\nDO_DEFAULT_REGION=fra1\n' > ~/.config/v2raygen/do.env
chmod 600 ~/.config/v2raygen/do.env
```

Optional settings in the same file: `DO_DEFAULT_SIZE` (default `s-1vcpu-512mb-10gb`), `DO_MAX_DROPLETS` (default `5`), `DO_SSH_PUBKEY` (path to a `.pub` file).

Usage:

```bash
python3 DOManager.py regions                              # available regions
python3 DOManager.py create --region fra1                 # new server; waits and prints the vless link
python3 DOManager.py create --region ams3 --sni www.cloudflare.com
python3 DOManager.py list                                 # servers
python3 DOManager.py list --links                         # servers with their vless links
python3 DOManager.py stop v2raygen-fra1-ab12              # shut down (DigitalOcean still bills it)
python3 DOManager.py start v2raygen-fra1-ab12             # power back on; same IP and link
python3 DOManager.py destroy v2raygen-fra1-ab12           # delete permanently; billing stops
```

DOManager only touches droplets tagged `v2raygen`. Links are cached in `~/.config/v2raygen/links.json`; use `list --links --refresh` to re-read them from the servers.
