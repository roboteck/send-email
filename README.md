##send-email

I needed a program that would be able to send emails with attachments from
the command line. Thus this small utility app was born.

```
usage: send-email.py -f FROM_ADDR -t TO_LIST [TO_LIST ...] [-h] [-v]
                     [-l LOG_FILE] [-U] [-V] [-r REPLY_TO]
                     [-c CC_LIST [CC_LIST ...]] [-b BCC_LIST [BCC_LIST ...]]
                     [-s SUBJECT] [-m MESSAGE]
                     [-a ATTACH_FILES [ATTACH_FILES ...]] [-x SMTP_SERVER]
                     [-o SMTP_PORT] [-e] [-u SMTP_USER] [-p SMTP_PASSWORD]

Required:
  -t, --to TO_LIST [TO_LIST ...]
                        Destination addresses.

Options:
  -h, --help            Show this help message and exit.
  -v, --verbose         Writes all messages to console.
  -l, --log-file  LOG_FILE
  -U, --update          Checks server for an update, replaces the current
                        version if there is a newer version available.
  -V, --version         show program's version number and exit

Email Options:
  -f, --from FROM_ADDR
                        From address on email.
  -r, --reply-to REPLY_TO
                        Reply to address.
  -c, --cc CC_LIST [CC_LIST ...]
                        Carbon copy addresses.
  -b, --bcc BCC_LIST [BCC_LIST ...]
                        Blind carbon copying addresses.
  -s, --subject SUBJECT
                        Subject of email.
  -m, --message MESSAGE
                        Content of email.
  -a, --attachment ATTACH_FILES [ATTACH_FILES ...]
                        File to attach to email.

SMTP Server Options:
  -x, --smtp-server SMTP_SERVER
                        The SMTP server to send email through.
  -o, --smtp-port SMTP_PORT
                        The port to use for the SMTP server.
  -e, --smtp-ssl        Use SSL when connecting too the SMTP server.
  -u, --smtp-user SMTP_USER
                        Authenticate with the SMTP server using this user.
  -p, --smtp-password SMTP_PASSWORD
                        Authenticate with the SMTP server using this password.

```

#### Installation Instructions

Run the following command:
```
SDIR=/usr/local/bin/; wget http://git.io/Uhy7VQ -O ${SDIR}/send-email && chmod +x ${SDIR}/send-email
```

Change the value of `SDIR` to change the destination directory.

#### Requirements
Requires the argparse library. If python version < 2.7 then install the library with pip or easy_install

```
pip install argparse
```
or
```
easy_install argparse
```
