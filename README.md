# check-dnssec-dnsviz - Check the DNSSEC status of a DNS zone

This is a check script for checking the DNSSEC status of a DNS zone using the instrumentation provided by the [DNSviz](https://github.com/dnsviz/dnsviz) project.

It is very similar to [Pieter Lexis' icinga-check-dns plugin](https://github.com/pieterlexis/icinga-check-dns), but uses a different approach of interfacing with DNSviz: Unlike icinga-check-dns it uses DNSviz' CLI tool of the same name instead of making use of the internal objects and classes of DNSviz.

While I personally find Pieter's approach more elegant than using the CLI tools, using the DNSviz classes is much more complex as there are no high-level classes, which is why this plugin exists.

## Installation

The plugin can be installed from PyPI using the `pip` command. It is highly recommended to use a virtual environment for installation:

```
export PLUGIN_PATH=/opt/check-dnssec-dnsviz/
mkdir $PLUGIN_PATH
python3 -m venv $PLUGIN_PATH/venv
$PLUGIN_PATH/venv/bin/python3 -m pip install --upgrade pip
$PLUGIN_PATH/venv/bin/python3 -m pip install check-dnssec-dnsviz
```

After installing, the plugin is available under the path `$PLUGIN_PATH/venv/bin/check_dnssec_dnsviz` for use with the monitoring tool of your choice.

If you prefer to keep all your plugins in your preferred distribution's standard path, e.g. `/usr/lib64/nagios/plugins` for RedHat-like distributions, you can symlink the `check_dnssec_dnsviz` script there:

```
ln -sf /opt/check-dnssec-dnsviz/venv/bin/check_dnssec_dnsviz.py /usr/lib64/nagios/plugins
```

## License

MIT
