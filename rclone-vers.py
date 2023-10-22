#!/usr/bin/env python3

import logging
import os
import re
import subprocess as sp
import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from configparser import ConfigParser
from dataclasses import dataclass
from datetime import datetime

from typing import TYPE_CHECKING, List, Optional
if TYPE_CHECKING:
    from argparse import Namespace


RCLONE = '/usr/bin/rclone'
DT_FMT = '%Y-%m-%d-%H%M%S'
__version__ = '0.2.0'


@dataclass
class VersionItem:
    """
    This is a convenience class to hold the data related to remote versioned
    files
    """
    path: str
    fname: str
    dt: datetime


def get_args() -> 'Namespace':
    """
    Get the CLI args
    """
    desc = 'This will allow you to, given a path to a file, decrypt an older ' \
        'version of the file'
    p = ArgumentParser(
        description=desc,
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    p.add_argument('-c', '--rclone-conf',
        default='/root/.config/rclone/rclone.conf',
        help='The path to the rclone config')
    p.add_argument('-r', '--crypt-remote', default='b2_secret',
        help='The name of the default encrypted remote from the rclone conf')
    p.add_argument('-l', '--crypt-local', default='local-crypt',
        help='The configuration for local enc. from the rclone.conf')
    p.add_argument('-e', '--enc-fname', help='You can optionally shortcut the '
        'search process by passing in the encrypted filename path')
    p.add_argument('-o', '--outdir', default='./',
        help='The directory to put the unencrypted file in')
    p.add_argument('-a', '--all-versions', action='store_true', default=False,
        help='Instead of prompting for which version to get, just get all '
        'previous versions (note that the *current* version will not be '
        'downloaded)')
    p.add_argument('-V', '--version', action='store_true', default=False,
        help='Print the version and exit')
    p.add_argument('-D', '--debug', action='store_true', default=False,
        help='Add debug output')
    p.add_argument('fname', nargs='?',
        help='The file to get an older version of')

    args = p.parse_args()

    if not args.version and not args.fname:
        p.error('You must supply a local filename')

    if not args.version and args.fname.startswith('/'):
        # Strip the leading / for compatability with the rclone output
        args.fname = args.fname[1:]

    return args


def setup_logging(args: 'Namespace') -> None:
    """
    This sets up default logging behavior
    """
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        format=(
            '%(asctime)s - %(levelname)s - '
            '%(filename)s:%(lineno)d %(funcName)s - %(message)s'
        ),
        level=level,
    )


def get_conf(args: 'Namespace') -> ConfigParser:
    """
    Read in the specified rclone config and return the config object
    """
    conf = ConfigParser()
    conf.read(args.rclone_conf)

    return conf


def get_enc_fname(conf: ConfigParser, args: 'Namespace') -> str:

    # First, we need to split the input file path so we can quickly build
    # the path to our target file
    loc_parts = args.fname.split('/')
    cmd_base = [RCLONE, '-v', '--crypt-show-mapping', 'lsd']
    rem_base = f'{args.crypt_remote}:'

    enc_path = ''
    num_parts = len(loc_parts)
    # We never need to run against the actual leaf
    for i, ppart in enumerate(loc_parts):
        if i == 0:
            # We are checking the root, which is just the bare base
            cmd = cmd_base + [rem_base]
        elif i == num_parts:
            # We won't actually run anything against the leaf as we already
            # have its name, just break.  This is setup with the zero
            # check first to handle the case of a file at the root of the
            # bucket
            break
        else:
            # We're checking an intermediate
            cmd = cmd_base + [f'{rem_base}{os.path.join(*loc_parts[:i])}']

        # We have our command, let's run it and get the enc name for what
        # we need
        regex = re.compile(r'NOTICE: ' + loc_parts[i] +
            r': Encrypts to "([^"]+)"')
        logging.debug(f'Running command: {" ".join(cmd)}')
        p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.STDOUT, encoding='utf-8',
            errors='ignore')

        for line in p.stdout:
            if m := regex.search(line):
                enc_path = os.path.join(enc_path, m.group(1))
                break

        if p.poll() is None:
            p.terminate()

    return enc_path


def get_version_list(
    enc_path: str,
    conf: ConfigParser,
    args: 'Namespace',
) -> List[VersionItem]:
    """
    This gets the list of versioned items for the given file
    """
    # Get the date and time of the version
    enc_dir, enc_fname = os.path.split(enc_path)
    regex = re.compile(r'\s(' + enc_fname + r'-v(\d{4}-\d+-\d+-\d+)-\d+)')
    rem = f'{conf[args.crypt_remote]["remote"]}/{enc_dir}'
    cmd = [RCLONE, '--b2-versions', 'ls', rem]
    p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.STDOUT, encoding='utf-8',
        errors='ignore')

    ret = []
    in_cap = False
    for line in p.stdout:
        if line.split()[1] == enc_fname:
            # Found the initial filename, set the var so we can shortcut after
            # getting the versions
            in_cap = True
            continue

        if in_cap:
            if m := regex.search(line):
                # We have a version, process it
                ret.append(VersionItem(
                    path=os.path.join(enc_dir, m.group(1)),
                    fname=m.group(1),
                    dt=datetime.strptime(m.group(2), DT_FMT),
                ))
            else:
                # We've gone through the versions, kill this process
                break
    if p.poll() is None:
        p.terminate()

    return ret


def prompt4vers(versions: List[VersionItem]) -> VersionItem:
    """
    Return the the obj matching the version selected
    """
    while True:
        print('Select the version you wish to restore:')
        for i, v in enumerate(versions):
            print(f'  {i + 1}: {v.dt}')

        sel = input('Which version?  ')
        # Get the version and verify the input
        try:
            sel = int(sel.strip())
        except Exception:
            print('You must enter a number, try again\n')
            continue

        if sel < 1 or sel > len(versions):
            print(f'Invalid selection "{sel}", try again\n')
            continue

        logging.debug(f'Version selected: {versions[sel - 1].dt}')

        # We have a good selection, return it
        return versions[sel - 1]


def get_loc_enc_dest(conf: ConfigParser, args: 'Namespace') -> str:
    """
    A shortcut function that pulls the temp directory from the rclone
    config for the local config
    """
    return conf[args.crypt_local]['remote'].split(':')[1]


def process_file(
    vi: VersionItem,
    conf: ConfigParser,
    args: 'Namespace',
) -> Optional[str]:
    """
    This will make some  filename changes and then unencrypt the file to
    a versioned name in the specified outdir. It also cleans up the encrypted
    file from the temp dir.
    """
    # Setup some variables for path names and such
    enc_dest = get_loc_enc_dest(conf, args)
    loc_enc_path = os.path.join(enc_dest, vi.fname)
    loc_enc_path_dest = loc_enc_path.split('-')[0]
    unenc_fname_base = os.path.basename(args.fname)
    unenc_fname_path = os.path.join(args.outdir, unenc_fname_base)
    unenc_final_path = (
        f'{unenc_fname_path}-{vi.fname.split("-", maxsplit=1)[1]}'
    )

    if not os.path.isdir(args.outdir):
        # Create the outdir
        os.makedirs(args.outdir, 0o700)

    # First, strip the datestamp portion of the encrypted filename
    os.rename(loc_enc_path, loc_enc_path_dest)

    # Now decrypt the file to the outdir
    cmd = [RCLONE, 'copy', f'{args.crypt_local}:{unenc_fname_base}',
        args.outdir]
    logging.debug(f'Running decrypt command: {" ".join(cmd)}')

    try:
        sp.run(cmd, capture_output=True, check=True)
    except Exception as e:
        logging.error(f'Failed to decrypt {loc_enc_path_dest} to '
            f'{args.outdir}, skipping this file: {e}')
        return None

    # Now we just need to rename the output file to its datestamped name
    os.rename(unenc_fname_path, unenc_final_path)

    # Remove the encrypted file
    os.unlink(loc_enc_path_dest)

    return unenc_final_path


def get_versions(
    versions: List[VersionItem],
    conf: ConfigParser,
    args: 'Namespace',
) -> None:
    """
    Given the list of versions to download, this will download them
    to the outdir with their filename-timestamp
    """
    enc_dest = get_loc_enc_dest(conf, args)
    if not os.path.isdir(enc_dest):
        # Create the local dest dir if it doesn't exist
        os.makedirs(enc_dest, 0o700)

    for vi in versions:
        cmd = [RCLONE, '--b2-versions', 'copy',
            f'{conf[args.crypt_remote]["remote"]}/{vi.path}',
            enc_dest,
        ]
        logging.debug(f'Saving {vi.path} to {args.outdir}')
        try:
            sp.run(cmd, capture_output=True, check=True)
        except Exception as e:
            logging.error(f'Error retrieving {vi.path}, skipping: {e}')
        else:
            if path := process_file(vi, conf, args):
                logging.info(f'Versioned file saved to: {path}')


def main() -> int:
    args = get_args()
    setup_logging(args)

    if args.version:
        print(f'{os.path.basename(__file__)}: {__version__}')
        return 0

    rcconf = get_conf(args)
    if args.enc_fname:
        enc_fname = args.enc_fname
    else:
        enc_fname = get_enc_fname(rcconf, args)
    logging.debug(f'Found encrypted filename for {args.fname}: {enc_fname}')

    versions = get_version_list(enc_fname, rcconf, args)
    logging.debug('Found encrypted file versions at times: '
        f'{[v.dt for v in versions]}')

    if not versions:
        logging.info(f'No versions found for {args.fname}, exiting')
        return 0

    vers_to_get = versions
    if not args.all_versions:
        vers_to_get = [prompt4vers(versions)]

    get_versions(vers_to_get, rcconf, args)

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
