# mail_monitor/management/commands/fetch_emails.py

import imaplib
import email
from email.header import decode_header
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils.timezone import make_aware
from django.core.files.base import ContentFile
from mail_monitor.models import EmailAccount, MonitoredEmail, EmailAttachment

class Command(BaseCommand):
    help = 'Fetches new emails from all active monitored accounts.'

    def handle(self, *args, **options):
        active_accounts = EmailAccount.objects.filter(is_active=True)
        self.stdout.write(f"Found {active_accounts.count()} active accounts to check.")

        for account in active_accounts:
            self.stdout.write(f"--- Checking account: {account.email_address} ---")
            try:
                password = account.get_decrypted_password()
                if not password:
                    self.stderr.write(self.style.ERROR(f"Could not decrypt password for {account.email_address}. Skipping."))
                    continue
                
                mail = imaplib.IMAP4_SSL(account.imap_server, account.imap_port)
                mail.login(account.email_address, password)
                
                self.fetch_from_folder(mail, account, 'INBOX')
                self.fetch_from_folder(mail, account, '"[Gmail]/Sent Mail"', is_sent_folder=True)
                self.fetch_from_folder(mail, account, 'Sent', is_sent_folder=True)

                mail.logout()
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"An error occurred with {account.email_address}: {e}"))
        
        self.stdout.write(self.style.SUCCESS("Email fetching complete."))

    def fetch_from_folder(self, mail, account, folder_name, is_sent_folder=False):
        status, _ = mail.select(folder_name, readonly=True)
        if status != 'OK':
            # This is not an error, the folder might just not exist (e.g., 'Sent' vs '[Gmail]/Sent Mail')
            return

        last_checked = account.last_checked_sent if is_sent_folder else account.last_checked_inbox
        search_date = (datetime.now() - timedelta(days=7)).strftime("%d-%b-%Y")
        search_criteria = f'(SINCE "{search_date}")'
        if last_checked:
            search_criteria = f'(SINCE {last_checked.strftime("%d-%b-%Y")})'
        
        status, messages = mail.search(None, search_criteria)
        if status != 'OK' or not messages[0]:
            return
        
        email_ids = messages[0].split()
        self.stdout.write(f"Found {len(email_ids)} new emails in '{folder_name}'.")

        for email_id in reversed(email_ids): # Process oldest first
            status, msg_data = mail.fetch(email_id, '(RFC822)')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    msg_id = msg.get('Message-ID')
                    if not msg_id or MonitoredEmail.objects.filter(message_id=msg_id).exists():
                        continue
                    
                    subject = self.decode_mime_words(msg['Subject'])
                    sender = self.decode_mime_words(msg.get('From'))
                    recipients = ", ".join(filter(None, [self.decode_mime_words(msg.get('To')), self.decode_mime_words(msg.get('Cc')), self.decode_mime_words(msg.get('Bcc'))]))

                    try:
                        email_date = make_aware(email.utils.parsedate_to_datetime(msg["Date"]))
                    except (TypeError, ValueError):
                        email_date = make_aware(datetime.now())
                    
                    body, attachments_found = self.extract_body_and_attachments(msg)
                    
                    new_email = MonitoredEmail.objects.create(
                        account=account, message_id=msg_id, folder=folder_name.strip('"'),
                        sender=sender, recipients=recipients, subject=subject, body=body,
                        date=email_date, has_attachments=bool(attachments_found)
                    )

                    for attachment_data in attachments_found:
                        EmailAttachment.objects.create(email=new_email, **attachment_data)
                    
                    self.stdout.write(f"  > Saved: '{subject}' {'(with attachments)' if attachments_found else ''}")

        if is_sent_folder:
            account.last_checked_sent = make_aware(datetime.now())
        else:
            account.last_checked_inbox = make_aware(datetime.now())
        account.save()

    def decode_mime_words(self, s):
        if not s: return ""
        decoded_string = ""
        for text, charset in decode_header(s):
            if isinstance(text, bytes):
                try:
                    decoded_string += text.decode(charset or 'utf-8', 'ignore')
                except:
                    decoded_string += str(text)
            else:
                decoded_string += text
        return decoded_string

    def extract_body_and_attachments(self, msg):
        body = ""
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition"))
                content_type = part.get_content_type()
                
                if "attachment" in content_disposition:
                    try:
                        filename = part.get_filename()
                        if filename:
                            attachments.append({
                                'filename': self.decode_mime_words(filename),
                                'content_type': content_type,
                                'file': ContentFile(part.get_payload(decode=True), name=self.decode_mime_words(filename))
                            })
                    except Exception as e:
                        self.stderr.write(f"Could not process attachment: {e}")
                elif content_type == "text/plain" and "attachment" not in content_disposition:
                    if not body: # Only get the first plain text part
                        body = part.get_payload(decode=True).decode('utf-8', 'ignore')
        else:
            body = msg.get_payload(decode=True).decode('utf-8', 'ignore')
        return body, attachments