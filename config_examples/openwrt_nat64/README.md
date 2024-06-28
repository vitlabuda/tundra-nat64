# Tundra – OpenWRT NAT64 configuration example


A Tundra instance with a very similar configuration to the one in this directory has been successfully deployed
on a *TP-Link TL-WR841N v13* running **OpenWRT 21.02.5**.

**WARNING:** As of now, this example does not work on OpenWRT 22.03 and later, as these versions do not have `iptables` 
installed (at least not by default), and the `firewall.user` script is not available there!

**This configuration assumes that your router has a dual-stack (both IPv4 and IPv6) connectivity, and that a NAT 
masquerade is performed on IPv4 packets going to your WAN interface. You might want to adjust interface names, 
IP addresses and file paths before deploying this configuration!** 


### Step-by-step guide:
1. Install the `kmod-tun`, `kmod-ipt-nat6`, `kmod-nf-nat6` and `kmod-nft-nat6` packages using `opkg`.

2. Cross-compile Tundra for your router's target using the OpenWRT SDK. See [this page](https://openwrt.org/docs/guide-developer/toolchain/crosscompile) for more information. For example:
   ```shell
   CC=mipsel-openwrt-linux-gcc cmake -S. -Bbuild
   make -Cbuild
   ```

3. Copy the compiled Tundra binary to your router (e.g. using `scp`). This configuration uses the following path: `/usr/local/sbin/tundra-nat64`.

4. Copy the Tundra configuration file, [`tundra-nat64.conf`](tundra-nat64.conf), to your router. This configuration uses the following path: `/etc/tundra-nat64/tundra-nat64.conf`. 
   
5. Copy the `procd` service file, [`tundra-nat64`](tundra-nat64), to your router – use the path `/etc/init.d/tundra-nat64`.

6. Configure your router's firewall – **append** the contents of [`firewall.user`](firewall.user) to `/etc/firewall.user` on your router.
   You may also edit this file using LuCI: Network --> Firewall --> Custom Rules.

7. Start the service by executing `/etc/init.d/tundra-nat64 start`, and if everything works correctly, enable it by executing `/etc/init.d/tundra-nat64 enable`, so it starts automatically on every boot. If you encounter any problems, you may try restarting your router.
