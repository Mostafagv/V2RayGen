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

### Examples

Pick a region, then create your first server:

```bash
python3 DOManager.py regions
# ams3   Amsterdam 3
# fra1   Frankfurt 1
# lon1   London 1
# ...

python3 DOManager.py create --region fra1
# Creating v2raygen-fra1-3f9a (id 512345678) in fra1 [s-1vcpu-512mb-10gb]
# Server is up at 203.0.113.10
#   waiting for setup to finish...
#
# Ready: v2raygen-fra1-3f9a
# vless://...@203.0.113.10:443?security=reality&...#xray
```

Create a server with your own name, a bigger size and a custom SNI:

```bash
python3 DOManager.py create --region ams3 --name proxy-ams --size s-1vcpu-1gb --sni www.cloudflare.com
```

Use a different REALITY destination or port:

```bash
python3 DOManager.py create --region lon1 --sni www.microsoft.com --reality-dest www.microsoft.com:443 --port 8443
```

Create several servers without waiting, then collect the links later:

```bash
python3 DOManager.py create --region fra1 --no-wait
python3 DOManager.py create --region sgp1 --no-wait
python3 DOManager.py list --links      # run again after a few minutes if a link is not ready yet
```

See your servers and their links:

```bash
python3 DOManager.py list
# v2raygen-fra1-3f9a           512345678  fra1   203.0.113.10     active   s-1vcpu-512mb-10gb
# proxy-ams                    512345901  ams3   203.0.113.25     off      s-1vcpu-1gb

python3 DOManager.py list --links
python3 DOManager.py list --links --refresh   # re-read links from the servers instead of the cache
```

Pause and resume a server (the IP and link stay the same, but DigitalOcean keeps billing while it is off):

```bash
python3 DOManager.py stop proxy-ams
python3 DOManager.py stop proxy-ams --force     # hard power-off if a clean shutdown hangs
python3 DOManager.py start proxy-ams
```

Replace a blocked server with a fresh one (new IP, new link):

```bash
python3 DOManager.py destroy v2raygen-fra1-3f9a
python3 DOManager.py create --region fra1
```

Destroy by id without the confirmation prompt (careful: this cannot be undone):

```bash
python3 DOManager.py destroy 512345678 --yes
```

Use a token for a single command without saving it to a file:

```bash
DIGITALOCEAN_TOKEN=dop_v1_... python3 DOManager.py list
```

Use a specific SSH key:

```bash
python3 DOManager.py create --region fra1 --ssh-pubkey ~/.ssh/do_proxy.pub
```

If setup fails, look at the server's setup log:

```bash
ssh root@203.0.113.10 tail -n 50 /var/log/cloud-init-output.log
```
