# Icinga integration for check-dnssec-dnsviz

This directory contains Icinga configuration files that enable the check-dnssec-dnsviz plugin in Icinga 2 environments.

## Command definition file

The file `commands-check-dnssec-dnsviz.conf` provides the `dnssec-dnsviz` CheckComamnd object. It must be copied to the global zone directory of the Icinga 2 master node so it is available for use in service definitions.

## Service definition file provides a framework to create DNSSEC check objects.

It takes a dictopnary from the host configuration and creates checks from it, applying individual settings to each check. This file must also be copied to the global zone directory of the Icinga 2 master node.

## Setting up DNSSEC checks

After the command and service definitions have been made available, hosts can be configured to check the DNSSEC status of zones by creating host variables like this:

```
object Host "master1" {
    [...]
    vars = {
        "dnssec" = {
            "fail01.dnssec.works" = {
                dnsviz_zone = "fail01.dnssec.works"
                dnsviz_authoritative = true
                dnsviz_expire_warn = 24
                dnsviz_expire_crit = 12
            }
            "fail02.dnssec.works" = {
                dnsviz_zone = "fail02.dnssec.works"
                dnsviz_resolver = "[2620:fe::fe]"
            }
            "fail03.dnssec.works" = {
                dnsviz_zone = "fail03.dnssec.works"
            }
            "fail04.dnssec.works" = {
                dnsviz_zone = "fail04.dnssec.works"
            }
            "icinga.com" = {
                dnsviz_zone = "icinga.com"
            }
            "sys4.de" = {
                dnsviz_zone = "sys4.de"
            }
        }
    }
    [...]
}
```

## SELinux considerations

The DNSviz toolkit uses some ports that are normally not allowed by SELiunx for use by Icinga 2 plugins by SELiunx. In the `selinux` sub-directory there is a policy file that can be applied to make it possible to run the plugin in SELinux environments.

To enable the policy, just copy the `.pp` file to the hosts running the plugin and load it using the following command:

```
semodule -i check-dnssec-dnsviz.pp
```
