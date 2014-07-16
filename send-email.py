#!/usr/bin/env python
# send-email.py
# GusE 2014.03.17 V0.1
"""
Send an email from the command line.
"""
__version__ = "0.1"

import getopt
import sys
import os
import subprocess
import traceback
import logging
import logging.handlers
import argparse
import tempfile

__app__ = os.path.basename(__file__)
__author__ = "Gus E"
__copyright__ = "Copyright 2014"
__credits__ = ["Gus E"]
__license__ = "GPL"
__maintainer__ = "Gus E"
__email__ = "gesquive@gmail"
__status__ = "Beta"


script_www = 'https://github.com/gesquive/send-email'
script_url = 'https://raw.github.com/gesquive/send-email/master/send-email.py'


#--------------------------------------
# Configurable Constants
LOG_FILE = '/var/log/' + os.path.splitext(__app__)[0] + '.log'
LOG_SIZE = 1024*1024*200

verbose = False
debug = False

logger = logging.getLogger(__app__)


def main():
    global verbose, debug

    verbose = False
    debug = False
    log_file = LOG_FILE

    #TODO: Add config file support. Example: https://gist.github.com/von/949337
    parser = argparse.ArgumentParser(add_help=False,
        description="Send an email from the command line.",
        epilog="%(__app__)s v%(__version__)s\n" % globals())
    group = parser.add_argument_group("Required")
    group.add_argument("-t", "--to", nargs="+", dest="to_list", required=True,
        help="Destination addresses.")

    group = parser.add_argument_group("Options")
    group.add_argument("-h", "--help", action="help",
        help="Show this help message and exit.")
    group.add_argument("-v", "--verbose", action="store_true", dest="verbose",
        help="Writes all messages to console.")
    group.add_argument("-d", "--debug", action="store_true", dest="debug",
        help=argparse.SUPPRESS)
    group.add_argument("-l", "--log-file", dest="log_file")
    group.add_argument("-U", "--update", action="store_true", dest="update",
        help="Checks server for an update, replaces the current version if "\
        "there is a newer version available.")
    group.add_argument("-V", "--version", action="version",
                    version="%(__app__)s v%(__version__)s" % globals())

    #TODO: Add HTML email support
    group = parser.add_argument_group("Email Options")
    group.add_argument("-f", "--from", dest="from_addr",
        default=get_default_from_email(), help="From address on email.")
    group.add_argument("-r", "--reply-to", help="Reply to address.")
    group.add_argument("-c", "--cc", nargs="+", dest="cc_list", default=[],
        help="Carbon copy addresses.")
    group.add_argument("-b", "--bcc", nargs="+", dest="bcc_list", default=[],
        help="Blind carbon copying addresses.")
    group.add_argument("-s", "--subject", dest="subject", type=str,
        help="Subject of email.")
    group.add_argument("-m", "--message", dest="message", type=str,
        help="Content of email.", default="")
    group.add_argument("-a", "--attachment", nargs="+", dest="attach_files",
        help="File to attach to email.", default=[])

    group = parser.add_argument_group("SMTP Server Options")
    group.add_argument("-x", "--smtp-server", default="localhost",
        help="The SMTP server to send email through.")
    group.add_argument("-o", "--smtp-port", type=int,
        help="The port to use for the SMTP server.")
    group.add_argument("-e", "--smtp-ssl", action="store_true",
        help="Use an SSL connection for the SMTP server.")
    group.add_argument("-u", "--smtp-user",
        help="Authenticate the SMTP server with this user.")
    group.add_argument("-p", "--smtp-password",
        help="Authenticate the SMTP server with this password.")

    args = parser.parse_args()
    verbose = args.verbose
    debug = args.debug

    if args.update:
        update(script_url)

    if not os.access(log_file, os.W_OK):
        # Couldn't write to the given log file, try writing a temporary one instead
        log_file = os.path.join(tempfile.gettempdir(),
            os.path.splitext(__app__)[0] + '.log')
        if not os.access(os.path.dirname(log_file), os.W_OK):
            print "ERROR: Cannot write to '%(log_file)s'.\nExiting." % locals()
            sys.exit(2)
    file_handler = logging.handlers.RotatingFileHandler(log_file,
                                            maxBytes=LOG_SIZE, backupCount=9)
    file_formater = logging.Formatter('%(asctime)s,%(levelname)s,%(thread)d,%(message)s')
    file_handler.setFormatter(file_formater)
    logger.addHandler(file_handler)

    if verbose:
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter("[%(asctime)s] %(levelname)-5.5s: %(message)s")
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    logger.setLevel(logging.DEBUG)

    try:
        # print args
        msg = Email(args.smtp_server, args.smtp_port, args.smtp_ssl,
            args.smtp_user, args.smtp_password)
        msg.set_from(args.from_addr)
        for address in args.to_list:
            msg.add_recipient(address)
        for address in args.cc_list:
            msg.add_cc_recipient(address)
        for address in args.bcc_list:
            msg.add_bcc_recipient(address)
        msg.clear_reply_to()
        if args.reply_to:
            msg.set_reply_to(args.reply_to)
        msg.set_subject(args.subject)
        msg.set_text_body(args.message)
        msg.clear_attachments()
        for attach_files in args.attach_files:
            msg.add_attachment(attach_files)

        try:
            msg.send()
        except smtplib.SMTPAuthenticationError, e:
            print "Authentication Error: %s" % str(e)
        except smtplib.SMTPHeloError, e:
            print "Handshake Error: %s" % str(e)
        except smtplib.SMTPConnectError, e:
            print "Connection Error: %s" % str(e)
        except smtplib.SMTPDataError, e:
            print "Data Error: %s" % str(e)
        except smtplib.SMTPRecipientsRefused, e:
            print "Recipients Refused Error: %s" % str(e)
        except smtplib.SMTPSenderRefused, e:
            print "Sender Refused Error: %s" % str(e)
        except smtplib.SMTPResponseException, e:
            print "Response Error: %s" % str(e)
        except smtplib.SMTPServerDisconnected, e:
            print "Server Disconnected Error: %s" % str(e)
        except smtplib.SMTPException, e:
            print "SMTP Error: %s" % str(e)
        except Exception, e:
            print "Error: %s" % str(e)
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception, e:
        print traceback.format_exc()
        print e


from socket import gethostname
from os import getlogin
def get_default_from_email():
    # Email should look like user@hostname.domain
    default = "%s@%s" % (getlogin(), gethostname())

    return default


# This class is based off of http://code.activestate.com/recipes/576858/ (r1)
from sys import version_info
if version_info[:2] == (2, 4):
    import email.Encoders as encoders
    from email.MIMEBase import MIMEBase
    from email.MIMEMultipart import MIMEMultipart
    from email.MIMEText import MIMEText
    from email.MIMEImage import MIMEImage
    from email.MIMEAudio import MIMEAudio
elif version_info[:2] >= (2, 5):
    from email import encoders
    from email.mime.base import MIMEBase
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.image import MIMEImage
    from email.mime.audio import MIMEAudio

import mimetypes
import os
import re
import smtplib

class Email:
    """
    This class handles the creation and sending of email messages
    via SMTP.  This class also handles attachments and can send
    HTML messages.  The code comes from various places around
    the net and from my own brain.
    """
    def __init__(self, smtp_server='localhost', smtp_port=None,
        smtp_ssl=False, smtp_user=None, smtp_password=None):
        """
        Create a new empty email message object.

        @param smtp_server: The address of the SMTP server
        @type smtp_server: String
        """
        self._text_body = None
        self._html_body = None
        self._subject = ""
        self._reply_to = None

        self._smtp_server = smtp_server
        self._smtp_port = smtp_port
        self._smtp_ssl = smtp_ssl
        self._smtp_user = smtp_user
        self._smtp_password = smtp_password

        self._re_email = re.compile("^([\\w \\._]+\\<[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\>|[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)$")
        self.clear_recipients()
        self.clear_attachments()

    def send(self):
        """
        Send the email message represented by this object.
        """
        # Validate message
        if self._text_body is None and self._html_body is None:
            raise Exception("Error! Must specify at least one body type (HTML or Text)")
        if len(self._to) == 0:
            raise Exception("Must specify at least one recipient")

        # Create the message part
        if self._text_body is not None and self._html_body is None:
            msg = MIMEText(self._text_body, "plain")
        elif self._text_body is None and self._html_body is not None:
            msg = MIMEText(self._html_body, "html")
        else:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(self._text_body, "plain"))
            msg.attach(MIMEText(self._html_body, "html"))
        # Add attachments, if any
        if len(self._attach) != 0:
            tmpmsg = msg
            msg = MIMEMultipart()
            msg.attach(tmpmsg)
        for fname,attachname in self._attach:
            if not os.path.exists(fname):
                print "File '%s' does not exist.  Not attaching to email." % fname
                continue
            if not os.path.isfile(fname):
                print "Attachment '%s' is not a file.  Not attaching to email." % fname
                continue
            # Guess at encoding type
            ctype, encoding = mimetypes.guess_type(fname)
            if ctype is None or encoding is not None:
                # No guess could be made so use a binary type.
                ctype = 'application/octet-stream'
            maintype, subtype = ctype.split('/', 1)
            if maintype == 'text':
                fp = open(fname)
                attach = MIMEText(fp.read(), _subtype=subtype)
                fp.close()
            elif maintype == 'image':
                fp = open(fname, 'rb')
                attach = MIMEImage(fp.read(), _subtype=subtype)
                fp.close()
            elif maintype == 'audio':
                fp = open(fname, 'rb')
                attach = MIMEAudio(fp.read(), _subtype=subtype)
                fp.close()
            else:
                fp = open(fname, 'rb')
                attach = MIMEBase(maintype, subtype)
                attach.set_payload(fp.read())
                fp.close()
                # Encode the payload using Base64
                encoders.encode_base64(attach)
            # Set the filename parameter
            if attachname is None:
                filename = os.path.basename(fname)
            else:
                filename = attachname
            attach.add_header('Content-Disposition', 'attachment', filename=filename)
            msg.attach(attach)
        # Some header stuff
        msg['Subject'] = self._subject
        msg['From'] = self._from
        msg['To'] = ", ".join(self._to)
        if self._reply_to:
            msg['Reply-To'] = self._reply_to
        if len(self._cc) > 0:
            msg['Cc'] = ", ".join(self._cc)
        if len(self._bcc) > 0:
            msg['Bcc'] = ", ".join(self._bcc)
        msg.preamble = "You need a MIME enabled mail reader to see this message"
        # Send message
        msg = msg.as_string()
        server = None
        if self._smtp_ssl:
            server = smtplib.SMTP_SSL(host=self._smtp_server,
                port=self._smtp_port)
        else:
            server = smtplib.SMTP(host=self._smtp_server, port=self._smtp_port)
        if self._smtp_user:
            server.login(self._smtp_user, self._smtp_password)
        server.sendmail(self._from, self._to, msg)
        server.quit()

    def set_subject(self, subject):
        """
        Set the subject of the email message.
        """
        self._subject = subject

    def set_from(self, address):
        """
        Set the email sender.
        """
        if not self.validate_email_address(address):
            raise Exception("Invalid email address '%s'" % address)
        self._from = address

    def clear_reply_to(self):
        self._reply_to = None

    def set_reply_to(self, address):
        """
        Set the reply too address.
        """
        if not self.validate_email_address(address):
            raise Exception("Invalid email address '%s'" % address)
        self._reply_to = address

    def clear_recipients(self):
        """
        Remove all currently defined recipients for
        the email message.
        """
        self._to = []
        self._cc = []
        self._bcc = []

    def add_recipient(self, address):
        """
        Add a new recipient to the email message.
        """
        if not self.validate_email_address(address):
            raise Exception("Invalid email address '%s'" % address)
        self._to.append(address)

    def add_cc_recipient(self, address):
        """
        Add a new recipient to the email message.
        """
        if not self.validate_email_address(address):
            raise Exception("Invalid email address '%s'" % address)
        self._cc.append(address)

    def add_bcc_recipient(self, address):
        """
        Add a new recipient to the email message.
        """
        if not self.validate_email_address(address):
            raise Exception("Invalid email address '%s'" % address)
        self._bcc.append(address)

    def set_text_body(self, body):
        """
        Set the plain text body of the email message.
        """
        self._text_body = body

    def set_html_body(self, body):
        """
        Set the HTML portion of the email message.
        """
        self._html_body = body

    def clear_attachments(self):
        """
        Remove all file attachments.
        """
        self._attach = []

    def add_attachment(self, fname, attachname=None):
        """
        Add a file attachment to this email message.

        @param fname: The full path and file name of the file
                      to attach.
        @type fname: String
        @param attachname: This will be the name of the file in
                           the email message if set.  If not set
                           then the filename will be taken from
                           the fname parameter above.
        @type attachname: String
        """
        if fname is None:
            return
        self._attach.append( (fname, attachname) )

    def validate_email_address(self, address):
        """
        Validate the specified email address.

        @return: True if valid, False otherwise
        @rtype: Boolean
        """
        if self._re_email.search(address.lower()) is None:
            return False
        return True


def update(dl_url, force_update=False):
    """
Attempts to download the update url in order to find if an update is needed.
If an update is needed, the current script is backed up and the update is
saved in its place.
"""
    import urllib
    import re
    from subprocess import call
    def compare_versions(vA, vB):
        """
Compares two version number strings
@param vA: first version string to compare
@param vB: second version string to compare
@author <a href="http_stream://sebthom.de/136-comparing-version-numbers-in-jython-pytho/">Sebastian Thomschke</a>
@return negative if vA < vB, zero if vA == vB, positive if vA > vB.
"""
        if vA == vB: return 0

        def num(s):
            if s.isdigit(): return int(s)
            return s

        seqA = map(num, re.findall('\d+|\w+', vA.replace('-SNAPSHOT', '')))
        seqB = map(num, re.findall('\d+|\w+', vB.replace('-SNAPSHOT', '')))

        # this is to ensure that 1.0 == 1.0.0 in cmp(..)
        lenA, lenB = len(seqA), len(seqB)
        for i in range(lenA, lenB): seqA += (0,)
        for i in range(lenB, lenA): seqB += (0,)

        rc = cmp(seqA, seqB)

        if rc == 0:
            if vA.endswith('-SNAPSHOT'): return -1
            if vB.endswith('-SNAPSHOT'): return 1
        return rc

    # dl the first 256 bytes and parse it for version number
    try:
        http_stream = urllib.urlopen(dl_url)
        update_file = http_stream.read(256)
        http_stream.close()
    except IOError, (errno, strerror):
        print "Unable to retrieve version data"
        print "Error %s: %s" % (errno, strerror)
        return

    match_regex = re.search(r'__version__ *= *"(\S+)"', update_file)
    if not match_regex:
        print "No version info could be found"
        return
    update_version = match_regex.group(1)

    if not update_version:
        print "Unable to parse version data"
        return

    if force_update:
        print "Forcing update, downloading version %s..." \
            % update_version
    else:
        cmp_result = compare_versions(__version__, update_version)
        if cmp_result < 0:
            print "Newer version %s available, downloading..." % update_version
        elif cmp_result > 0:
            print "Local version %s newer then available %s, not updating." \
                % (__version__, update_version)
            return
        else:
            print "You already have the latest version."
            return

    # dl, backup, and save the updated script
    app_path = os.path.realpath(sys.argv[0])

    if not os.access(app_path, os.W_OK):
        print "Cannot update -- unable to write to %s" % app_path

    dl_path = app_path + ".new"
    backup_path = app_path + ".old"
    try:
        dl_file = open(dl_path, 'w')
        http_stream = urllib.urlopen(dl_url)
        total_size = None
        bytes_so_far = 0
        chunk_size = 8192
        try:
            total_size = int(http_stream.info().getheader('Content-Length').strip())
        except:
            # The header is improper or missing Content-Length, just download
            dl_file.write(http_stream.read())

        while total_size:
            chunk = http_stream.read(chunk_size)
            dl_file.write(chunk)
            bytes_so_far += len(chunk)

            if not chunk:
                break

            percent = float(bytes_so_far) / total_size
            percent = round(percent*100, 2)
            sys.stdout.write("Downloaded %d of %d bytes (%0.2f%%)\r" %
                (bytes_so_far, total_size, percent))

            if bytes_so_far >= total_size:
                sys.stdout.write('\n')

        http_stream.close()
        dl_file.close()
    except IOError, (errno, strerror):
        print "Download failed"
        print "Error %s: %s" % (errno, strerror)
        return

    try:
        os.rename(app_path, backup_path)
    except OSError, (errno, strerror):
        print "Unable to rename %s to %s: (%d) %s" \
            % (app_path, backup_path, errno, strerror)
        return

    try:
        os.rename(dl_path, app_path)
    except OSError, (errno, strerror):
        print "Unable to rename %s to %s: (%d) %s" \
            % (dl_path, app_path, errno, strerror)
        return

    try:
        import shutil
        shutil.copymode(backup_path, app_path)
    except:
        os.chmod(app_path, 0755)

    print "New version installed as %s" % app_path
    print "(previous version backed up to %s)" % (backup_path)
    return


if __name__ == '__main__':
    main()
