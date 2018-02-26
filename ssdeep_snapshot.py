#!/usr/bin/env python

"""
ssdeep_snapshot.py -- by Daniel Roberson @dmfroberson 7/4/2017
                   -- Gathers information about files and stores in a sqlite3
                   -- database for future analysis/comparison.

Currently very rough!!

TODO:
- argparse
  -- verbose output -- shows full output for use with --stdin piping

- stdin option to run over network, but store on another machine ex:
  -- ssh user@host ssdeep-snapshot.py /bin | ssdeep-snapshot --db=foo.db --stdin
     This would run the snapshot tool for /bin on "host", but store it locally
     within "foo.db".

- lookup tool: ssdeep-snapshot-lookup <database> <hostname> <path>
  -- delete option for this tool to remove entries
  -- update option for this tool to update entries
  -- maybe just use sqlite3 instead of making tools? its easy enough..

- Script or instructions for importing into mysql/postgres (sqlfairy)
  -- Useful for dealing with massive amounts of data

- Add actual usernames/groups in addition to uid/gid

- Change verbiage of "directories" because it also corresponds to files

- General code cleanup!!
"""

# needs python-ssdeep, python-magic, and python-sqlite

import os
import sys
import sqlite3
import socket
import stat
import argparse
import ssdeep
import hashlib
import magic

DEFAULT_DIRECTORIES = [
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin"
]

HOSTNAME = socket.getfqdn()


def parse_cli():
    """ parse_cli() -- parses CLI input

    Args:
        None

    Returns:
        ArgumentParser namespace relevant to supplied CLI input
    """
    description = "example: ./ssdeep_snapshot.py [-v] [-d <file>] dir dir2 dirN"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-d",
                        "--database",
                        help="sqlite3 database file to store results",
                        default="ssdeep-snapshot.db")
    parser.add_argument("-q",
                        "--quiet",
                        help="Suppress unnecessary output",
                        action="store_true")
    parser.add_argument("--hostname",
                        help="Specify hostname identifier rather getfqdn()",
                        default=HOSTNAME)
    parser.add_argument("directories",
                        help="Directories to walk",
                        nargs=argparse.REMAINDER,
                        action="store")

    args = parser.parse_args()
    return args


def add_db_record(cursor, filename, quiet):
    """
    docstring
    """
    absolute = os.path.abspath(filename)
    try:
        tempstat = os.stat(absolute)
        perms = oct(tempstat.st_mode)
        owner = tempstat.st_uid
        group = tempstat.st_gid
        size = tempstat.st_size
    except OSError as err:
        print "[-] Couldn't open %s: %s" % (absolute, err)
        return False

    # Calculate ssdeep hash
    try:
        fuzzy_hash = ssdeep.hash_from_file(absolute)
    except IOError:
        fuzzy_hash = "PERMISSION DENIED"
    except UnicodeDecodeError:
        fuzzy_hash = "UNICODE DECODE ERROR"

    # Calculate MD5 hash
    md5hash = hashlib.md5()
    md5hash.update(open(absolute).read())

    # Calculate SHA1 hash
    sha1hash = hashlib.sha1()
    sha1hash.update(open(absolute).read())

    # Determine file type with libmagic
    filetype = magic.detect_from_filename(absolute).name

    if quiet is False:
        print "[+] Adding %s -- %s" % (filename, filetype)

    cursor.execute(
        "INSERT INTO hashes VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME())",
           (HOSTNAME,
            absolute,
            size,
            perms,
            owner,
            group,
            fuzzy_hash,
            md5hash.hexdigest(),
            sha1hash.hexdigest(),
            filetype))

    return True


def walk_directory(cursor, directory, quiet):
    """
    docstring
    """
    if not os.path.exists(directory):
        print "[-] No such file or directory: %s" % directory
        return False

    # Process individual file
    if not os.path.isdir(directory):
        return add_db_record(cursor, directory, quiet)

    # Walk directory
    for dirname, _, filelist in os.walk(directory):
        print "[+] Walking %s" % directory
        for filename in filelist:
            fullname = os.path.join(dirname, filename)
            sys.stdout.write("  ")
            add_db_record(cursor, fullname, quiet)

    return True


def main():
    """ main()
    Args:
        None

    Returns:
        EX_OK on success
        EX_USAGE on failure
    """
    print "[+] ssdeep-snapshot.py -- By Daniel Roberson @dmfroberson"
    print

    global HOSTNAME
    args = parse_cli()
    dbfile = args.database
    HOSTNAME = args.hostname

    if args.directories:
        directories = args.directories
    else:
        directories = DEFAULT_DIRECTORIES


    print "[+] Using sqlite3 database file: %s" % dbfile
    try:
        con = sqlite3.connect(dbfile)
    except sqlite3.OperationalError as err:
        print "[-] sqlite3.connect(%s): %s" % (dbfile, err)
        print "[-] Exiting."
        return os.EX_USAGE

    # This might be wrong, look into it!
    con.text_factory = str

    # Create schema if it doesn't exist
    cursor = con.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS hashes(hostname TEXT, filename TEXT, " + \
        "size INT, perm INT, uid TEXT, gid TEXT, hash_ssdeep TEXT, " + \
        "hash_md5 TEXT, hash_sha1 TEXT, filetype TEXT, date_added DATEIME)")

    # Walk the supplied directories/filenames
    for directory in directories:
        walk_directory(cursor, directory, args.quiet)
        con.commit()

    con.close()

    print "[+] Done."
    return os.EX_OK


if __name__ == "__main__":
    exit(main())
