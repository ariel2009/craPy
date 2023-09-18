# This class responsible for providing comfortable cli
import click
import os
from Tools import Scan
from enum import Enum


# Constructor for root command
class CraPy(object):
    def __init__(self, home=None, debug=False):
        self.homev = os.path.abspath(home or '.')
        self.debug = debug


# creating mandatory cli options
@click.group()
@click.option('--repo-home', envvar='REPO_HOME', default=' .repo')
@click.option('--debug/--no-debug', default=False,
              envvar='REPO_DEBUG')
@click.pass_context
def cli(ctx, repo_home, debug):
    ctx.obj = CraPy(repo_home, debug)


# This is the help msg once hitting main,py --help
@cli.command(help="Scan for open ports or alive hosts")
# Define the cli options of the tool
@click.option('-sA', help='scan for alive hosts by arp pings', required=False)
@click.option('-h', help='provide an ip address', required=False)
@click.option('-p', help='scan for open ports', required=False)
# Call the Scan class to Scan ip/host/port depending on the selected option
def scan(sa, h, p):
    if sa:
        scan_addr_obj = Scan.Scan(sa)
        scan_addr_obj.print_arp_scan()
    elif h and p:
        scan_addr_obj = Scan.Scan(h, p)
        scan_addr_obj.port_scan()
