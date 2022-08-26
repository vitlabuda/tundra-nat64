# Tundra – Debian CLAT configuration example


A Tundra instance with a very similar configuration to the one in this directory has been successfully deployed on a 
machine running **Debian 11 Bullseye**. However, the configuration does not rely on any Debian-specific features, so it 
should be possible to use it (possibly with some small adjustments) on any Linux distribution that uses `systemd`.

**This configuration assumes that you have a machine with no native IPv4 connectivity, and that servers in IPv4 Internet
are accessed through your network's NAT64 translator. You might want to adjust interface names, IP addresses and 
file paths before deploying this configuration!** 


### Step-by-step guide:
1. Since the next step will enable your computer to behave as a router, you should appropriately configure the
   `FORWARD` chain of your firewall for both IPv4 and IPv6 (using `iptables` and `ip6tables`) to prevent security issues.

2. Enable IPv4 and IPv6 forwarding by adding the following lines to `/etc/sysctl.conf`:
   ```
   net.ipv4.ip_forward=1
   net.ipv6.conf.all.forwarding=1
   ```
   Apply the configuration changes by executing `sysctl -p`.

   **NOTE:** If IPv6 forwarding is enabled, Linux kernel will stop accepting Router Advertisements (RA), so IPv6
   autoconfiguration might stop working after you perform this step. To enable it again, add `net.ipv6.conf.all.accept_ra=2`
   to `/etc/sysctl.conf`. If your machine uses some out-of-kernel solution to manage its network configuration, such as
   `NetworkManager`, you may not encounter this problem.

3. Compile Tundra using `gcc` or `clang`:
   ```shell
   gcc -Wall -Wextra -pthread -std=c11 -O3 -flto -o tundra-nat64 src/t64_*.c
   ```

4. Copy the compiled Tundra binary to a path from which it will be executed. You might also want to change the 
   executable's ownership to `root`. This configuration uses the following path: `/usr/local/sbin/tundra-nat64`.

5. Copy the Tundra configuration file, [tundra-clat.conf](tundra-clat.conf), to a path from which it will be loaded
   by Tundra. This configuration uses the following path: `/usr/local/etc/tundra-clat/tundra-clat.conf`.

6. Copy the start script, [start-tundra.sh](start-tundra.sh), and the stop script, [stop-tundra.sh](stop-tundra.sh), to
   an appropriate directory. This configuration uses the following paths: `/usr/local/etc/tundra-clat/start-tundra.sh` 
   for the start script, and `/usr/local/etc/tundra-clat/stop-tundra.sh` for the stop script.
   
   **NOTE:** If you changed some options in the Tundra configuration file, you should check if the values of the 
   variables in the scripts still match the program's configuration!

7. Copy the `systemd` service file, [tundra-clat.service](tundra-clat.service), to 
   `/etc/systemd/system/tundra-clat.service` (or `/lib/systemd/system/tundra-clat.service`), and apply the change by
   executing `systemctl daemon-reload`.

8. Start the service by executing `systemctl start tundra-clat`. If you encounter any problems, you may try restarting 
   your machine.

   **NOTE:** It is not recommended to enable the service so it starts automatically on boot, because it would break your
   network connectivity on networks where native IPv4 is present and NAT64 is not used. Instead, it is recommended to 
   start the service manually, on-demand (using `systemctl start tundra-clat`), or you might add a hook to your network
   configuration management software (such as `NetworkManager`), which would detect whether NAT64 is present and start
   the CLAT translator if so.
