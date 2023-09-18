import click
import os
from Tools import Scan
from enum import Enum


class CraPy(object):
    def __init__(self, home=None, debug=False):
        self.homev = os.path.abspath(home or '.')
        self.debug = debug


@click.group()
@click.option('--repo-home', envvar='REPO_HOME', default=' .repo')
@click.option('--debug/--no-debug', default=False,
              envvar='REPO_DEBUG')
@click.pass_context
def cli(ctx, repo_home, debug):
    ctx.obj = CraPy(repo_home, debug)


@cli.command(help="Scan for open ports or alive hosts")
# @click.option('-p', help="protocols or ports to scan", required=False)
@click.option('-sA', help='scan for alive hosts by arp pings', required=False)
@click.option('-h',help='provide an ip address',required=False)
@click.option('-p',help='scan for open ports', required=False)
@click.option('-t', help='Amount of Threads', required=False, default="10")
def scan(sa, h, p, t):
    if sa:
        scan_addr_obj = Scan.Scan(sa)
        scan_addr_obj.print_arp_scan()
    elif h and p:
        scan_addr_obj = Scan.Scan(h, p)
        scan_addr_obj.port_scan()